class Logger:

    verbose = False  # set by Scanner(debug=...)

    @staticmethod
    def info(message):
        print(f"[INF] {message}")

    @staticmethod
    def success(message):
        print(f"[OK ] {message}")

    @staticmethod
    def warning(message):
        print(f"[WRN] {message}")

    @staticmethod
    def error(message):
        print(f"[ERR] {message}")

    @staticmethod
    def debug(message):
        if Logger.verbose:
            print(f"[DBG] {message}")
