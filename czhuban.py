import resolver
import sys
import arg_parser


def main():  # pragma: no cover
    args = arg_parser.parse_args(sys.argv[1:])
    a_rrs = resolver.resolve(args)
    for rr in a_rrs:
        print('domain name: ' + str(rr.name))
        print('ip: ' + str(rr.data.ip))
        print()


if __name__ == '__main__':  # pragma: no cover
    main()
