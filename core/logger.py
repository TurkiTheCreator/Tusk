class Logger:

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
        
