import ipaddress  # pragma: no cover
import socket  # pragma: no cover
import sys  # pragma: no cover

from utils import resolver  # pragma: no cover
from utils import arg_parser  # pragma: no cover
from utils.zhuban_exceptions import InvalidServerResponse  # pragma: no cover
from dns.dns_enums import RRType  # pragma: no cover


def main():  # pragma: no cover
    args = arg_parser.parse_args(sys.argv[1:])

    try:
        answer = resolver.resolve(args)

    except socket.timeout:
        print("timed out", file=sys.stderr)
        sys.exit(1)
    except socket.gaierror:
        print("address-related error", file=sys.stderr)
        sys.exit(1)
    except InvalidServerResponse:
        print("invalid server response", file=sys.stderr)
        sys.exit(1)
    except ConnectionError:
        print('connection-related error', file=sys.stderr)
        sys.exit(1)

    print('Server response:\n\t' + answer.header.response_type.name,
          end='\n\n')
    for answer in answer.answers:
        if answer.type_ == RRType.A:
            print('A', answer.name, answer.data.ip, sep='\t')
        elif answer.type_ == RRType.AAAA:
            print('AAAA', answer.name,
                  ipaddress.IPv6Address(answer.data.ip).compressed, sep='\t')
        elif answer.type_ == RRType.PTR:
            ip = answer.name.strip('.in-addr.arpa').split('.')
            print('PTR', '.'.join(reversed(ip)), answer.data.name, sep='\t')
        elif answer.type_ == RRType.NS:
            print('NS', answer.data.name, sep='\t')
        elif answer.type_ == RRType.SOA:
            print('SOA',
                  answer.data.name_server,
                  answer.data.email_addr,
                  answer.data.serial_number,
                  answer.data.refresh,
                  answer.data.retry,
                  answer.data.expiry,
                  answer.data.nxdomain_ttl,
                  sep='\t')
        elif answer.type_ == RRType.TXT:
            print('TXT', answer.data.text, sep='\t')
        elif answer.type_ == RRType.MX:
            print('MX', answer.data.preference, answer.data.name, sep='\t')
        elif answer.type_ == RRType.CNAME:
            print('CNAME', answer.data.cname, sep='\t')
        print()


if __name__ == '__main__':  # pragma: no cover
    main()
