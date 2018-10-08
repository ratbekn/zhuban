import resolver
import sys
import arg_parser


def main():  # pragma: no cover
    args = arg_parser.parse_args(sys.argv[1:])
    answer = resolver.resolve(args.hostname, args.rtype)
    for answer in answer.answers:
        print('domain name: ' + str(answer.name))
        print('record type: ' + str(answer.type_))
        print('record class: ' + str(answer.class_))
        print('time to live: ' + str(answer.ttl))
        print('data length: ' + str(answer.length))
        print('ip: ' + str(answer.data.ip))
        print()


if __name__ == '__main__':  # pragma: no cover
    main()
