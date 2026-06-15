import argparse

from secure_chat.server_app import SecureChatServer


def build_parser():
    parser = argparse.ArgumentParser(description="Servidor do chat seguro.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--data-dir", default="server_state")
    return parser


def main():
    args = build_parser().parse_args()
    server = SecureChatServer(host=args.host, port=args.port, data_dir=args.data_dir)
    server.serve_forever()


if __name__ == "__main__":
    main()
