class Logger:
    COLORS = {
        "INFO": "\033[92m",
        "DEBUG": "\033[94m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m",
        "CRITICAL": "\033[31m",
        "SUCCESS": "\033[1;92m",
        "VULN": "\033[1;95m",
    }

    RESET = "\033[0m"

    def log(self, level, message):
        level = level.upper()
        color = self.COLORS.get(level)

        if color:
            if level == "VULN":
                # bold for entire line
                print(f"{color}[{level}] {message}{self.RESET}")
            else:
                print(f"{color}[{level}]{self.RESET} {message}")
        else:
            print(f"[{level}] {message}")

    # shortcuts
    def info(self, msg): self.log("INFO", msg)
    def debug(self, msg): self.log("DEBUG", msg)
    def warning(self, msg): self.log("WARNING", msg)
    def error(self, msg): self.log("ERROR", msg)
    def critical(self, msg): self.log("CRITICAL", msg)
    def success(self, msg): self.log("SUCCESS", msg)
    def vuln(self, msg): self.log("VULN", msg)