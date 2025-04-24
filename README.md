# Fraud Detection in Prolog

A rule-based fraudulent transaction detection application in Prolog.

## Files in the repository

1. **transactions_1000.pl**  
   This file contains the knowledge base with transaction data. It holds the facts for different transactions including their amounts, origin, destination, device, and other relevant attributes.

2. **fraud_rules.pl**  
   This file implements the fraud detection rules. It is a console-based Prolog program.  
   **Steps to run**:
   - Make sure you have Prolog installed on your system. You can download it from [SWI-Prolog's official website](https://www.swi-prolog.org/Download.html).
   - Open a terminal or command prompt.
   - Navigate to the directory containing the `fraud_rules.pl` file.
   - Run the following command:
     ```bash
     swipl
     ```
   - Load the file by typing:
     ```prolog
     ?- [fraud_rules].
     ```
   - To check for fraudulent transactions, use the following Prolog commands (the methods are written and commented in the code):
     ```prolog
     ?- check_fraud(tx3)
     ?- check_temp_transaction(tx1001, 510619, 19, 'india', 'australia', 0.5, 'branch', 'desktop', yes, no).
     ```
   
3. **fraud_expert_system.pl**  
   This is a UI-based version of the fraud detection system. It uses a simple web interface where you can input transaction data to check for fraud.  
   **Steps to run**:
   - Make sure you have Prolog installed on your system. You can download it from [SWI-Prolog's official website](https://www.swi-prolog.org/Download.html).
   - Open a terminal or command prompt.
   - Navigate to the directory containing the `fraud_expert_system.pl` file.
   - Start SWI-Prolog by typing:
     ```bash
     swipl
     ```
   - Load the system by running:
     ```prolog
     ?- [fraud_expert_system].
     ```
   - Start the server by running:
     ```prolog
     ?- start_server(8081).
     ```
     *(Note: You can change the port number as per your preference.)*
   - Open your browser and go to `http://localhost:8081` to interact with the system.

