const whois = require('whois');;

const MATCH_WHOIS_RANGE = /(# start)((.*\n)*?)(# end)/gm;;
const MATCH_NET_RANGE = /(NetRange)((.*\n)*?)(^\n)/gm;;
const MATCH_ORG = /(OrgName)((.*\n)*?)(^\n)/gm;;
const MATCH_HANDLES = /(.*?Handle)((.*\n)*?)(^\n)/gm;;
const MATCH_LINE_KEY = /.*?(?=:)/g;;
const MATCH_LINE_KEY_EXTENDED = /(^.*?:[ ]*)(?=.*)/g;;
const MATCH_ORG_ID = /(?<=\().*(?=\))/;;
const ARIN_TO_RPSL_MATRIX = {
    "NetRange": "inetnum",
    "NetName": "netname",
    "NetType": "status",
    "Organization": "org",
    "RegDate": "created",
    "Updated": "last-modified",
    "Comment": "remarks",
    "OrgName": "org-name",
    "OrgId": "organisation",
    "Address": "address",
    "City": "address",
    "StateProv": "address",
    "PostalCode": "address",
    "Country": "address",
    "OrgAbuseHandle": "nic-hdl",
    "OrgAbuseName": "role",
    "OrgAbusePhone": "phone",
    "OrgAbuseEmail": "e-mail",
    "OrgTechHandle": "nic-hdl",
    "OrgTechName": "role",
    "OrgTechPhone": "phone",
    "OrgTechEmail": "e-mail",
};;

function convert_to_rpsl(str) {
    let return_str = "";;
    str.split('\n').map(line => {
        if (line.length === 0) return;;
        const key = line.match(MATCH_LINE_KEY)[0];;
        const value = line.replace(MATCH_LINE_KEY_EXTENDED, '');;
        switch (key) {
            case "RegDate": case "Updated":
                return_str += (ARIN_TO_RPSL_MATRIX[key] + ":").padEnd(17, ' ') + new Date(value).toISOString() + "\n";;
                break;;
            case "Organization":
                return_str += (ARIN_TO_RPSL_MATRIX[key] + ":").padEnd(17, ' ') + value.match(MATCH_ORG_ID)[0] + "\n";;
                break;;
            default:
                if (typeof ARIN_TO_RPSL_MATRIX[key] === "undefined") break;;
                return_str += (ARIN_TO_RPSL_MATRIX[key] + ":").padEnd(17, ' ') + value + "\n";;
                break;;
        }
    });;
    return_str += "mnt-by:".padEnd(17, ' ') + "ARIN-HM-UNKNDOWN-MNT\n";;
    return_str += "source:".padEnd(17, ' ') + "ARIN\n";;
    return return_str;;
}

whois.lookup('n + 23.139.40.23', {
    server: 'whois.arin.net'
}, function(err, data) {
    const range = data.match(MATCH_WHOIS_RANGE)[1];;
    const net = range.match(MATCH_NET_RANGE);;
    const org = range.match(MATCH_ORG);;
    const handles = range.match(MATCH_HANDLES).filter(handle => !handle.startsWith('NetHandle'));;

    console.log(convert_to_rpsl(net[0]));;
    console.log(convert_to_rpsl(org[0]));;
    handles.map(handle => console.log(convert_to_rpsl(handle)));;
});;