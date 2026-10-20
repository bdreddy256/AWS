for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws ec2 describe-security-groups --region "$r" --output text \
    --query "SecurityGroups[].[sum([length(IpPermissions[].IpRanges[]),length(IpPermissions[].Ipv6Ranges[]),length(IpPermissions[].UserIdGroupPairs[]),length(IpPermissions[].PrefixListIds[])]),'$r',GroupId,GroupName]"
done | sort -nr
