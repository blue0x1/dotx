# dotx v 1.0

*A stealthy hunter for exposed dotfiles and misconfigured secrets*
<br><br>

![dotx-removebg-preview](https://github.com/user-attachments/assets/3ec8ca49-8f86-41f1-87ef-0c5f8b098892)

---
## Features
-  **Depth charge scanning** - Crawl up to 5 levels deep (default: 2)
-  **Stealth mode** - Disguises as Chrome browser traffic
-  **Secret sniffer** - Detects AWS keys, GitHub tokens, and other,..
-  **JSON export** - Structured output 



---

## Installation
```bash
git clone https://github.com/blue0x1/dotx 
cd dotx
go build -o dotx
sudo mv dotx /usr/local/bin
```

---

## Usage
basic recon
```bash
dotx https://example.com
```

![New Project](https://github.com/user-attachments/assets/690ae714-4dd6-44c2-b556-05163d9d56dc)

extended 

```bash
dotx -t 50 -d 3 -code 200 -o autopsy-report.json https://api.example.com 
```

![image psd](https://github.com/user-attachments/assets/5888a6f3-f5f8-4c5e-93ff-a7a7d20572c7)



 ## Flags

| Flag     | What it does                      | Default |
|----------|-----------------------------------|---------|
| `-t`     | Threads                           | `20`    |
| `-d`     | Depth                             | `2`     |
| `-o`     | Output file  (JSON)               | `-`     |
| `-code`  | Filter by HTTP status code        | `0`     |

## ⚠️ Legal Disclaimer  
**For educational/authorized use only.**  
By using this code:  
- Test ONLY systems you own/have permission to scan  
- Unauthorized use violates laws (CFAA, GDPR, etc.)  
- Developer assumes no liability for misuse  

*Created by [@blue0x1](https://github.com/blue0x1) - Not a hacking tool*
