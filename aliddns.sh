#!/bin/bash

aliddns_interval=600
aliddns_ak=
aliddns_sk=
aliddns_domain=""
aliddns_name=""
aliddns_domain2=""
aliddns_name2=""
aliddns_domain6=""
aliddns_name6=""
aliddns_ttl=600

user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4792.0 Safari/537.36'

IPv6=0
domain_type=""
hostIP=""
domain=""
name=""
name1=""
timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
aliddns_record_id=""

aliddns_start(){
    if [ "$aliddns_domain"x != "x" ] && [ "$aliddns_name"x != "x" ] ; then
		timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
		aliddns_record_id=""
		domain="$aliddns_domain"
		name="$aliddns_name"
		arDdnsCheck $aliddns_domain $aliddns_name
	fi
    if [ "$aliddns_domain2"x != "x" ] && [ "$aliddns_name2"x != "x" ] ; then
		sleep 1
		timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
		aliddns_record_id=""
		domain="$aliddns_domain2"
		name="$aliddns_name2"
		arDdnsCheck $aliddns_domain2 $aliddns_name2
	fi
    if [ "$aliddns_domain6"x != "x" ] && [ "$aliddns_name6"x != "x" ] ; then
		sleep 1
		IPv6=1
		timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
		aliddns_record_id=""
		domain="$aliddns_domain6"
		name="$aliddns_name6"
		arDdnsCheck $aliddns_domain6 $aliddns_name6
	fi

    source "$ddns_script"
    while read line
	do
		line=`echo $line | cut -d '#' -f1`
		line=$(echo $line)
		[ -z "$line" ] && continue
		sleep 1
		IPv6=1
		timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
		IPv6_neighbor=1
		aliddns_record_id=""
		name="$(echo "$line" | cut -d '@' -f1)"
		domain="$(echo "$line" | cut -d '@' -f2)"
		inf_MAC="$(echo "$line" | cut -d '@' -f3 | tr 'A-Z' 'a-z')"
		inf_match="$(echo "$line" | cut -d '@' -f4)"
		inf_v_match="$(echo "$line" | cut -d '@' -f5)"
		[ -z "$inf_v_match" ] && inf_v_match="inf_v_match"
		inet6_neighbor="$(echo "$line" | cut -d '@' -f6)"
		inet6_neighbor=$(echo $inet6_neighbor)
		if [ -z "$inet6_neighbor" ] ; then
			ip -f inet6 neighbor show > /tmp/ip6_neighbor.log
			inet6_neighbor="$(cat /tmp/ip6_neighbor.log | grep "$inf_MAC" | grep -v "$inf_v_match" | grep "$inf_match" | awk -F ' ' '{print $1}' | sed -n '1p')"
		fi
        [ ! -z "$inet6_neighbor" ] && arDdnsCheck $domain $name
		IPv6_neighbor=0
	done < /tmp/ip6_ddns_inf
}

urlencode() {
	# urlencode <string>
	out=""
	read S
	for i in $(seq 0 $(($(echo -n "$S" |awk -F "" '{print NF}') - 1)) )
	do
		c="${S:$i:1}"
		case "$c" in
			[-_.~a-zA-Z0-9]) out="$out$c" ;;
			*) out="$out`printf '%%%02X' "'$c"`" ;;
		esac
	done
	echo -n $out
}

enc() {
	echo -n "$1" | urlencode
}

send_request() {
	args="AccessKeyId=$aliddns_ak&Action=$1&Format=json&$2&Version=2015-01-09"
	hash=$(echo -n "GET&%2F&$(enc "$args")" | openssl dgst -sha1 -hmac "$aliddns_sk&" -binary | openssl base64)
	curl -L    -s "http://alidns.aliyuncs.com/?$args&Signature=$(enc "$hash")"
	sleep 1
}

get_recordid() {
	grep -Eo '"RecordId":"[0-9]+"' | cut -d':' -f2 | tr -d '"' |head -n1
}

get_recordIP() {
	sed -e "s/"'"TTL":'"/"' \n '"/g" | grep '"Type":"'$domain_type'"' | grep -Eo '"Value":"[^"]*"' | awk -F 'Value":"' '{print $2}' | tr -d '"' |head -n1
}

query_recordInfo() {
	send_request "DescribeDomainRecordInfo" "RecordId=$1&SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&Timestamp=$timestamp"
}

query_recordid() {
	send_request "DescribeSubDomainRecords" "SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&SubDomain=$name1.$domain&Timestamp=$timestamp&Type=$domain_type"
}

update_record() {
	hostIP_tmp=$(enc "$hostIP")
	send_request "UpdateDomainRecord" "RR=$name1&RecordId=$1&SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&TTL=$aliddns_ttl&Timestamp=$timestamp&Type=$domain_type&Value=$hostIP_tmp"
}

add_record() {
	hostIP_tmp=$(enc "$hostIP")
	send_request "AddDomainRecord&DomainName=$domain" "RR=$name1&SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&TTL=$aliddns_ttl&Timestamp=$timestamp&Type=$domain_type&Value=$hostIP_tmp"
}

arDdnsInfo() {
	case  $name  in
		\*)
			name1=%2A
			;;
		\@)
			name1=%40
			;;
		*)
			name1=$name
			;;
	esac

	if [ "$IPv6" = "1" ]; then
		domain_type="AAAA"
	else
		domain_type="A"
	fi
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
	# ????????????ID
	aliddns_record_id=""
	aliddns_record_id=`query_recordid | get_recordid`
	sleep 1
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
	# ??????????????????IP
	recordIP=`query_recordInfo $aliddns_record_id | get_recordIP`
	
	if [ "$IPv6" = "1" ]; then
		echo $recordIP
		return 0
	else
		# Output IP
		case "$recordIP" in 
		[1-9]*)
			echo $recordIP
			return 0
			;;
		*)
			aliddns_record_id=""
			echo "Get Record Info Failed!"
			echo "???AliDDNS?????????????????????????????????????????? recordIP:$recordIP "
			return 1
			;;
		esac
	fi
}

# ??????????????????
# ??????: ???????????????
arNslookup() {
	mkdir -p /tmp/arNslookup
	nslookup $1 | tail -n +3 | grep "Address" | awk '{print $3}'| grep -v ":" | sed -n '1p' > /tmp/arNslookup/$$ &
	I=5
	while [ ! -s /tmp/arNslookup/$$ ] ; do
		I=$(($I - 1))
		[ $I -lt 0 ] && break
		sleep 1
	done
	killall nslookup
	if [ -s /tmp/arNslookup/$$ ] ; then
		cat /tmp/arNslookup/$$ | sort -u | grep -v "^$"
		rm -f /tmp/arNslookup/$$
	else
		curltest=`which curl`
		if [ -z "$curltest" ] || [ ! -s "`which curl`" ] ; then
			Address="`wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- http://119.29.29.29/d?dn=$1`"
			if [ $? -eq 0 ]; then
				echo "$Address" |  sed s/\;/"\n"/g | sed -n '1p' | grep -E -o '([0-9]+\.){3}[0-9]+'
			fi
		else
			Address="`curl --user-agent "$user_agent" -s http://119.29.29.29/d?dn=$1`"
			if [ $? -eq 0 ]; then
				echo "$Address" |  sed s/\;/"\n"/g | sed -n '1p' | grep -E -o '([0-9]+\.){3}[0-9]+'
			fi
		fi
	fi
}

arNslookup6() {
	mkdir -p /tmp/arNslookup
	nslookup $1 | tail -n +3 | grep "Address" | awk '{print $3}'| grep ":" | sed -n '1p' > /tmp/arNslookup/$$ &
	I=5
	while [ ! -s /tmp/arNslookup/$$ ] ; do
		I=$(($I - 1))
		[ $I -lt 0 ] && break
		sleep 1
	done
	killall nslookup
	if [ -s /tmp/arNslookup/$$ ] ; then
		cat /tmp/arNslookup/$$ | sort -u | grep -v "^$"
		rm -f /tmp/arNslookup/$$
	else
		curltest=`which curl`
		if [ -z "$curltest" ] || [ ! -s "`which curl`" ] ; then
			Address="$(wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- --header 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name='"$1"'&type=AAAA')"
			if [ $? -eq 0 ]; then
				echo "$Address" | grep -Eo "data\":\"[^\"]+" | sed "s/data\":\"//g" | sed -n '1p'
			fi
		else
			Address="$(curl --user-agent "$user_agent" -s -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name='"$1"'&type=AAAA')"
			if [ $? -eq 0 ]; then
				echo "$Address" | grep -Eo "data\":\"[^\"]+" | sed "s/data\":\"//g" | sed -n '1p'
			fi
		fi
	fi
}

arDdnsUpdate() {
	case  $name  in
		\*)
			name1=%2A
			;;
		\@)
			name1=%40
			;;
		*)
			name1=$name
			;;
	esac
	if [ "$IPv6" = "1" ]; then
		domain_type="AAAA"
	else
		domain_type="A"
	fi
	I=3
	aliddns_record_id=""
	while [ -z "$aliddns_record_id" ] ; do
		I=$(($I - 1))
		[ $I -lt 0 ] && break
		# ????????????ID
		timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
		aliddns_record_id=`query_recordid | get_recordid`
		echo "recordID $aliddns_record_id"
		sleep 1
	done
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
	if [ -z "$aliddns_record_id" ] ; then
		aliddns_record_id=`add_record | get_recordid`
		echo "added record $aliddns_record_id"
		echo "???AliDDNS??????????????? ???????????????  $aliddns_record_id"
	else
		update_record $aliddns_record_id
		echo "updated record $aliddns_record_id"
		echo "???AliDDNS??????????????? ???????????????  $aliddns_record_id"
	fi
	# save to file
	if [ -z "$aliddns_record_id" ] ; then
		# failed
		
		aliddns_last_act="`date "+%Y-%m-%d %H:%M:%S"`   ???????????? aliddns_record_id: $aliddns_record_id "
        echo "???AliDDNS??????????????? ???????????? $aliddns_last_act"
		return 1
	else
		
		aliddns_last_act="`date "+%Y-%m-%d %H:%M:%S"`   ???????????????$hostIP"
        echo "???AliDDNS??????????????? ??????????????? $hostIP"
		return 0
	fi

}

# ??????????????????
# ??????: ????????? ?????????
arDdnsCheck() {
	#local postRS
	#local lastIP
	source "$ddns_script"
	hostIP=$arIpAddress
	hostIP=`echo $hostIP | head -n1 | cut -d' ' -f1`
	if [ -z $(echo "$hostIP" | grep : | grep -v "\.") ] && [ "$IPv6" = "1" ] ; then 
		IPv6=0
		echo "???AliDDNS??????????????? ?????????$hostIP ???????????? IPv6 ????????????????????????????????????????????????????????????IPv6??????(??????:ff03:0:0:0:0:0:0:c1)"
		return 1
	fi
	if [ "$hostIP"x = "x"  ] ; then
		curltest=`which curl`
		if [ -z "$curltest" ] || [ ! -s "`which curl`" ] ; then
			[ "$hostIP"x = "x"  ] && hostIP=`wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- "http://members.3322.org/dyndns/getip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- "ip.3322.net" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- "http://myip.ipip.net" | grep "?????? IP" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- "http://ddns.oray.com/checkip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
		else
			[ "$hostIP"x = "x"  ] && hostIP=`curl -L --user-agent "$user_agent" -s "http://members.3322.org/dyndns/getip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`curl -L --user-agent "$user_agent" -s ip.3322.net | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`curl -L --user-agent "$user_agent" -s "http://myip.ipip.net" | grep "?????? IP" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`curl -L --user-agent "$user_agent" -s http://ddns.oray.com/checkip | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
		fi
		if [ "$hostIP"x = "x"  ] ; then
			echo "???AliDDNS??????????????? ????????????????????? IP ?????????????????????????????????????????????"
			return 1
		fi
	fi
	echo "Updating Domain: $2.$1"
	echo "hostIP: $hostIP"
	lastIP=$(arDdnsInfo "$1 $2")
	if [ $? -eq 1 ]; then
		[ "$IPv6" != "1" ] && lastIP=$(arNslookup "$2.$1")
		[ "$IPv6" = "1" ] && lastIP=$(arNslookup6 "$2.$1")
	fi
	echo "lastIP: $lastIP"
	if [ "$lastIP" != "$hostIP" ] ; then
		echo "???AliDDNS??????????????? ???????????? $2.$1 ?????? IP ??????"
		echo "???AliDDNS??????????????? ?????? IP: $hostIP"
		echo "???AliDDNS??????????????? ?????? IP: $lastIP"
		aliddns_record_id=""
		sleep 1
		postRS=$(arDdnsUpdate "$1" "$2")
		if [ $? -eq 0 ]; then
			echo "postRS: $postRS"
			echo "???AliDDNS??????????????? ????????????DNS???????????????"
			return 0
		else
			echo $postRS
			echo "???AliDDNS??????????????? ????????????DNS???????????????????????????????????????"
			if [ "$IPv6" = "1" ] ; then 
				IPv6=0
				echo "???AliDDNS??????????????? ?????????$hostIP ???????????? IPv6 ????????????????????????????????????????????????????????????IPv6??????(??????:ff03:0:0:0:0:0:0:c1)"
				return 1
			fi
			return 1
		fi
	fi
	echo $lastIP
	echo "Last IP is the same as current IP!"
	return 1
}

initconfig () {
	ddns_script=~/aliddns/ddns_script.sh
	if [ ! -s "$ddns_script" ] ; then
        mkdir -p ~/aliddns
		cat > "$ddns_script" <<-\EEE
		# ??????????????????????????????????????????IP??????????????????#?????????
		arIpAddress () {
			# IPv4????????????
			# ??????????????????
			curltest=`which curl`
			if [ -z "$curltest" ] || [ ! -s "`which curl`" ] ; then
				#wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- "https://www.cloudflare.com/cdn-cgi/trace" | awk -F= '/ip/{print $2}'
				#wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- "http://myip.ipip.net" | grep "?????? IP" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
				wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- "http://members.3322.org/dyndns/getip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
				#wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- "ip.3322.net" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
				#wget -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- "http://ddns.oray.com/checkip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
			else
				#curl -L --user-agent "$user_agent" -s "https://www.cloudflare.com/cdn-cgi/trace" | awk -F= '/ip/{print $2}'
				#curl -L --user-agent "$user_agent" -s "http://myip.ipip.net" | grep "?????? IP" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
				curl -L --user-agent "$user_agent" -s "http://members.3322.org/dyndns/getip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
				#curl -L --user-agent "$user_agent" -s ip.3322.net | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
				#curl -L --user-agent "$user_agent" -s http://ddns.oray.com/checkip | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
			fi
		}
		arIpAddress6 () {
			# IPv6????????????
			# ????????????ipv6??????nat ipv6???????????????????????????
			ifconfig | awk '/Global/{print $3}' | awk -F/ '{print $1}'
			#curl -6 -s https://www.cloudflare.com/cdn-cgi/trace | awk -F= '/ip/{print $2}'
		}
		if [ "$IPv6_neighbor" != "1" ] ; then
			if [ "$IPv6" = "1" ] ; then
				arIpAddress=$(arIpAddress6)
			else
				arIpAddress=$(arIpAddress)
			fi
		else
			arIpAddress6_pd=$(arIpAddress6)
   			arIpAddress6_pd=`echo $arIpAddress6_pd | head -n1 | cut -d' ' -f1`
			if [ ! -z $(echo "$arIpAddress6_pd" | grep : | grep -v "\.") ] ; then
				inet6_neighbor_prefix=$(echo $arIpAddress6_pd | awk -F: '{print $1":"$2":"$3":"$4":"}')
				inet6_neighbor="${inet6_neighbor_prefix}${inet6_neighbor}"
			else
        		inet6_neighbor=""
    		fi
			arIpAddress=$inet6_neighbor
			inet6_neighbor=""
			IPv6_neighbor=0
		fi

		# ?????? ip -f inet6 neighbor show ?????????????????????????????? ddns ?????????????????????????????? IPV6 ????????????
		# ????????????????????? @ ?????????????????????????????? ????????? ???MAC?????????????????????
		# ?????????????????????ip6????????????????????? ?????????????????????ip6????????????????????? ???????????????ip????????????????????? 
		# ????????????????????????????????????????????????#????????????
		cat >/tmp/ip6_ddns.inf <<-\EOF
		#www@google.com@09:9B:9A:90:9F:D9@@fe80::@  # ??????????????????
		#www@google.com@09:9B:9A:90:9F:D9@@fe80::@990d:53c5:ce4d:5166


		EOF
		cat /tmp/ip6_ddns.inf | grep -v '^#'  | grep -v "^$" > /tmp/ip6_ddns_inf
		rm -f /tmp/ip6_ddns.inf
		EEE
		chmod 755 "$ddns_script"
	fi

}

initconfig
aliddns_start
