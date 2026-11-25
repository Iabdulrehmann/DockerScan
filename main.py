"""main.py - DockerScan entry point. No arguments = desktop app; with arguments = command line."""
import sys


def main():
    if len(sys.argv) > 1:                       # e.g.  python main.py scan image.tar
        import cli
        sys.exit(cli.main())
    import tkinter as tk
    from tkinter import messagebox
    try:
        from desktop_app import DockerScanApp
    except ImportError as e:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("DockerScan - missing dependency",
                             f"{e}\n\nInstall the requirements with:\n  pip install -r requirements.txt")
        sys.exit(1)
    DockerScanApp().mainloop()


if __name__ == "__main__":
    main()
