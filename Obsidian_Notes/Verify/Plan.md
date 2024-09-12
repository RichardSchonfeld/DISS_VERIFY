
1. **Abstract**  

     

2. **Project theme, objectives, and introduction**  

     

    - Applicant reasoning  

    - Employed perspective  

- **Table of contents**  

- **Aknowledgements**  

- **Background:**  

    - Blockchain  

    - Eth  

    - Shamir  

    - Digital signatures  

        - Ask GPT if there's more?  

- **Web3 and its adoption**  

- **Related works:**  

    - Existing Systems  

        - Blockcerts, and look for other competitors  

            - Compare approach to mine  

        - Traditional centralized credential verification platforms and their shortcoming  

            - Why is my app permanent?  

                - Server goes down for a classical model, data is lost  

                - Data remains on-chain here, and the user has the certificate  

                - Showcase why once the process follows through, the user has the certificate, and the signature is registered on the blockchain, why this is going to stand  

        - Hybrid authentication models  

        - Any literature on blockchain and IPFS in Credential Verification?  

- **Problem definition and requirements**  

    - Define what the system must achieve (use GPT for more discussion on this)  

    - Problem scope  

        - Clarify specific aspects of credential verification the project must address  

        - Challenges in current systems  

            - High gas fees  

            - Lack of user autonomy  

            - Reliance on third parties  

            - Privacy issues with centralization  

         

1. **Project architecture**  

    1. Implementation  

        1. Technologies used  

            1. Programming langauges (Solidity, Python, JS)  

            2. Platforms (Ethereum, IPFS)  

    - Start with a diagram  

        - --TBD--  

        - Process:  

            - Credential submission process  

            - IPFS Upload and metadata linking  

            - Smart contract execution on ethereum  

            - Shamir's secret sharing key management and reconstruction  

            - Signing process  

            - Verification process  

        - Security features and considerations:  

            - Encryption methods  

            - How Shamir protects data here  

- **Security analysis**  

    - Threat model:  

        - Define a set of potential threats (key compromise, server attack, on-chain manipulation) -- this will likely require shamir to be encrypted in some form  

    - Vulnerability assessment  

        - Mitigations of threats  

        - Private key expose  

        - Data tampering attempts with signing  

        - Talk about inability to reconstruct anything from just the signature  

    - Privacy and integrity  

        - User privacy maintenance evaluation, particularily sensitive credentials  

        - Discuss tamper-proofness of credentials  

- **Performance cost analysis**  

    - Gas cost optimalization techniques  

        - IPFS, On-server DB, etc.  

    - Storage efficiency  

        - Evaluate storage efficiency of IPFS  

    - System performance?  

        - Measure performance of key processes, such as verification, key reconstruction, and blockchain interaction  

- **Discussion**  

    - Advantages of the system  

        - Summarize benefits of the decentralized credential verification  

            - Improved user control  

            - Reduced reliance on third parties  

            - Highlighted better privacy  

            - Onboarding for non-web3-savvy users  

            - Ability to pull the wallet out  

    - Compare with existing systems  

    - Limitations  

- **Conclusion and future work**  

    - Aknowledge potential challenges  

        - Scalability, IDK what else, will look into this  

    - Future work  

        - Potential improvements  

        - Expansion into other sectors  

- **Contributions**  

    - Hybrid onboarding  

    - Shamir secret sharing allowing flexibility of data  

    - Any other aspects that are novel and good