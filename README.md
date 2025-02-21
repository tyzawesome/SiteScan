SiteScan - A Simple Security Misconfiguration Scanner

SiteScan is a C# console application designed for educational purposes to demonstrate basic cybersecurity concepts. This tool scans a given host for:

    Open Ports (checks if commonly used network ports are accessible)
    Exposed Web Paths (identifies sensitive files like /robots.txt, /.git/, /admin)
    Missing Security Headers (analyzes HTTP responses for misconfigurations)

WARNING: ETHICAL USE ONLY!

This tool is for educational purposes ONLY.

    DO NOT use this tool on any system you do not own or without explicit permission.
    Unauthorized scanning may be illegal and violate security laws like the Computer Fraud and Abuse Act (CFAA).
    The author is not responsible for misuse of this software.

Running the Program

    Clone the Repository:
    git clone https://github.com/tyzawesome/SiteScan.git
    cd SiteScan
Build the Program: 

    dotnet build
        
Run the Scanner:

    dotnet run

    Enter a Target Host when prompted (Example: scanme.nmap.org).

Limitations & Disclaimers

    This tool only performs basic scanning and should not be used as a real penetration testing or security assessment tool.
    It does NOT attempt any form of brute-force, exploitation, or vulnerability exploitation.
    It does NOT replace professional security tools
    Users must comply with ethical hacking guidelines and legal restrictions.

Ethical Considerations & Responsible Use
Potential Misuse Risks

This tool could be misused if modified by an unethical user:

    It could be automated for large-scale unauthorized port scans.
    It might be used on systems without consent, violating cybersecurity laws.
    If misunderstood, it might give users a false sense of security—this is a basic scanner, not a full security suite.
