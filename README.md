
# Guardian Key Recovery Flask API Server

This repository contains the Flask API server that powers the Guardian Key Recovery Snap. This Snap, developed by CryptoSat for the ETHGlobal NYC Hackathon, offers MetaMask users a simple way to recover their accounts using social recovery. By leveraging satellite-backed infrastructure, this solution ensures high levels of auditing and confidentiality.

## Getting Started

### Prerequisites

- Python (3.8 or later)
- pip
- Flask
- A virtual environment (optional but recommended). 

### Local Deployment

1. **Clone the Repository**

   ```shell
   git clone https://github.com/cryptosat/satlock_api
   cd satlock_api
   ```

2. **Setup Virtual Environment (Optional)**

   ```shell
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**

   ```shell
   pip install -r requirements.txt
   ```

4. **Run the Flask Server**

   ```shell
   flask run
   ```

## Usage with the Front End

While this repository provides the backend services, you'll need to pair it with the front-end Snap to get the full experience. You can find the frontend repository and its setup guide [here](https://github.com/cryptosat/satlock).

---

For detailed instructions on the Guardian Key Recovery process, please refer to the front-end repository's [Guardian Key Recovery Guide](https://github.com/cryptosat/satlock#guardian-key-recovery-guide).
