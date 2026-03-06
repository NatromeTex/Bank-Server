import subprocess
import sys

RULE_PREFIX = "AutoBlock"

def run_command(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        print("Command failed:", e)

def ban_ip(ip):
    rule_name = f"{RULE_PREFIX}_{ip}"
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    run_command(cmd)
    print(f"[OK] IP banned: {ip}")

def unban_ip(ip):
    rule_name = f"{RULE_PREFIX}_{ip}"
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    run_command(cmd)
    print(f"[OK] IP unbanned: {ip}")

def main():
    print("Mitigation Tool CLI")
    print("Commands:")
    print("  ban_ip <ip>")
    print("  unban_ip <ip>")
    print("  exit")

    while True:
        try:
            user_input = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            continue

        parts = user_input.split()

        if parts[0] == "exit":
            break

        if len(parts) != 2:
            print("Invalid command")
            continue

        cmd, ip = parts

        if cmd == "ban_ip":
            ban_ip(ip)
        elif cmd == "unban_ip":
            unban_ip(ip)
        else:
            print("Unknown command")

if __name__ == "__main__":
    main()