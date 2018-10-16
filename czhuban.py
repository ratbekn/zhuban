import resolver
import sys
import arg_parser


def main():  # pragma: no cover
    args = arg_parser.parse_args(sys.argv[1:])
    answer = resolver.resolve(args)
    for answer in answer.answers:
        print('domain name: ' + str(answer.name))
        print('IPv4: ' + str(answer.data.ip))
        print()


if __name__ == '__main__':  # pragma: no cover
    main()
