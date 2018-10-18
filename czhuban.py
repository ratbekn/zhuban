import sys
import arg_parser
from dns_enums import ResourceRecordType


def main():  # pragma: no cover
    args = arg_parser.parse_args(sys.argv[1:])
    answer = args.func(args)
    print('Server response: ' + answer.header.response_type.name, end='\n\n')
    for answer in answer.answers:
        if answer.type_ == ResourceRecordType.A:
            print('domain name: ' + answer.name)
            print('IPv4: ' + answer.data.ip)
        elif answer.type_ == ResourceRecordType.PTR:
            print('IPv4: ' + answer.name)
            print('domain name: ' + answer.data.name)


if __name__ == '__main__':  # pragma: no cover
    main()
