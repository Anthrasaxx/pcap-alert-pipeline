import subprocess
import sys

def run_script(script_name):
    print(f"\n🚀 Running: {script_name}")
    result = subprocess.run(["python3", script_name])
    if result.returncode != 0:
        print(f"❌ Failed: {script_name}")
        sys.exit(1)
    print(f"✅ Finished: {script_name}")

if __name__ == "__main__":
    try:
        # Step 0: Analyze PCAP file (will use capture.pcap automatically)
        run_script("t2.py")
        
        # Step 1: Detect malicious IPs
        run_script("abuseip.py")
        
        # Step 2: Generate Groq LLM recommendations
        run_script("groq2.py")
        
        # Step 3: Convert CSV to Excel
        run_script("csv_to_xlsx.py")
        
        # Step 4: create a jira ticket lert email
        run_script("jira.py")
        
        print("\n🎉 All steps completed successfully.")
    except KeyboardInterrupt:
        print("\n🛑 Pipeline interrupted by user.")
        sys.exit(1)
