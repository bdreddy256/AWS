from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs
from html import escape
import boto3
from awslogin import GetAWSCredentials

HOST, PORT = '0.0.0.0', 5100

HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title> List ENIs </title>
</head>
<body>
    <h2> List ENIs </h2>
    <form action="/" method="post">
        <input type="text" name="account" id="account" placeholder="Enter Account" value="__ACCOUNT__">
        <input type="text" name="search-term" id="search-term" placeholder="Enter Search IP" value="__TERM__">
        <input type="submit" value="Submit">
    </form>
"""

RESULTS = """
    <p>Total ENIs: __COUNT__</p>
    <input type="text" id="search-bar" placeholder="Search for rules..." onkeyup="filterTable()" />
    <p id="result-count">Total Matching Items: 0</p>
    <table border="1" id="data-table">
        <thead>
            <tr>
                <th onclick="sortTable(0)">IP Addresses</th>
                <th onclick="sortTable(1)">Security Group IDs</th>
                <th onclick="sortTable(2)">Security Group Names</th>
                <th onclick="sortTable(3)">ENI</th>
                <th onclick="sortTable(4)">Availability Zone</th>
                <th onclick="sortTable(5)">Status</th>
                <th onclick="sortTable(6)">Description</th>
            </tr>
        </thead>
        <tbody>
__ROWS__
        </tbody>
    </table>
    <script>
        function filterTable() {
            const query = document.getElementById("search-bar").value.toLowerCase();
            const rows = document.querySelectorAll("#data-table tbody tr");
            let count = 0;
            rows.forEach(row => {
                const match = Array.from(row.querySelectorAll("td")).some(cell =>
                    cell.textContent.toLowerCase().includes(query));
                row.style.display = match ? "" : "none";
                if (match) count++;
            });
            document.getElementById("result-count").textContent = `Total Matching Items: ${count}`;
        }

        let sortDirection = [true, true, true, true, true, true, true];
        function sortTable(columnIndex) {
            const tbody = document.querySelector("#data-table tbody");
            const rows = Array.from(tbody.rows);
            const isAscending = sortDirection[columnIndex];
            rows.sort((rowA, rowB) => {
                const cellA = rowA.cells[columnIndex].textContent.trim();
                const cellB = rowB.cells[columnIndex].textContent.trim();
                if (isNaN(cellA) || isNaN(cellB)) {
                    return isAscending ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
                }
                return isAscending ? parseFloat(cellA) - parseFloat(cellB) : parseFloat(cellB) - parseFloat(cellA);
            });
            rows.forEach(row => tbody.appendChild(row));
            sortDirection[columnIndex] = !isAscending;
        }

        document.addEventListener("DOMContentLoaded", function () {
            document.querySelectorAll(".copyable").forEach(cell => {
                cell.addEventListener("click", function () {
                    const text = cell.textContent.trim();
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(text)
                            .then(() => console.log(`Copied to clipboard: ${text}`))
                            .catch(err => console.error("Failed to copy text: ", err));
                    } else {
                        const textarea = document.createElement("textarea");
                        textarea.value = text;
                        document.body.appendChild(textarea);
                        textarea.select();
                        try {
                            document.execCommand("copy");
                            console.log(`Copied to clipboard: ${text}`);
                        } catch (err) {
                            console.error("Fallback: Failed to copy text: ", err);
                        }
                        document.body.removeChild(textarea);
                    }
                });
            });
        });
    </script>
"""

TAIL = """
</body>
</html>"""


def search(account, term):
    GetAWSCredentials(account)
    search_terms = term.strip().lower().split()
    response = boto3.client('ec2').describe_network_interfaces()['NetworkInterfaces']
    data = []
    for item in response:
        description = item.get('Description', '').lower()
        private_ips = [ip['PrivateIpAddress'] for ip in item.get('PrivateIpAddresses', [])]
        groups = item.get('Groups', [])
        sg_ids = [g['GroupId'] for g in groups]
        sg_names = [g['GroupName'] for g in groups]
        eni = item.get('NetworkInterfaceId', '')
        az = item.get('AvailabilityZone', '')
        status = item.get('Status', '').lower()
        fields = [description, eni.lower(), az.lower(), status] + \
                 [x.lower() for x in private_ips + sg_ids + sg_names]
        if any(t in f for t in search_terms for f in fields):
            data.append({'private_ips': private_ips, 'sg_ids': sg_ids, 'sg_names': sg_names,
                         'eni': eni, 'az': az, 'status': status, 'description': description})
    return data


def cell(value):
    if isinstance(value, list):
        value = ''.join(escape(v) + '<br>' for v in value)
    else:
        value = escape(value)
    return '                <td class="copyable">' + value + '</td>\n'


def render(account='', term='', data=None, error=''):
    page = HEAD.replace('__ACCOUNT__', escape(account)).replace('__TERM__', escape(term))
    if error:
        page += '    <p style="color:red">Error: ' + escape(error) + '</p>\n'
    elif data:
        rows = ''
        for d in data:
            rows += '            <tr>\n'
            for key in ('private_ips', 'sg_ids', 'sg_names', 'eni', 'az', 'status', 'description'):
                rows += cell(d[key])
            rows += '            </tr>\n'
        page += RESULTS.replace('__COUNT__', str(len(data))).replace('__ROWS__', rows)
    return (page + TAIL).encode('utf-8')


class Handler(BaseHTTPRequestHandler):
    def _send(self, body):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(render())

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        form = parse_qs(self.rfile.read(length).decode('utf-8'))
        account = form.get('account', ['NA'])[0]
        term = form.get('search-term', [''])[0]
        try:
            self._send(render(account, term, search(account, term)))
        except Exception as e:
            self._send(render(account, term, error=str(e)))


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True


if __name__ == '__main__':
    print('Serving on http://{}:{}'.format(HOST, PORT))
    Server((HOST, PORT), Handler).serve_forever()
