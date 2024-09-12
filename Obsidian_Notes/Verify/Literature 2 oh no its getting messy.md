https://eprint.iacr.org/2016/771.**pdf**


### Super useful Shamir video
https://www.youtube.com/watch?v=kkMps3X_tEE&t=97s


### Migrating from RSA to wallet
1. Encrypt RSA private key using Pk from wallet
2. System decrypts the private key - not sure where the private key will be stored in encrypted form
3. Voila

### IPFS Storage system
https://www.youtube.com/watch?v=hnigvVuoaIA&ab_channel=OurNetworks

- Instead of accessing content by location like file://path/to/file.ext we use ipfs://hash-of-file (aka "content identifier")
	- Hashes are deterministic so we can also verify it matches the stuff - maybe do something with this aswell?
		- Also means the same thing cannot live twice on IPFS, as you don't have 2 different address spaces
- Folders in IPFS are just files that have lists of hashes
- LOOK INTO MERGKLE-DAGs


###### Potentially useful links:
- Django integration with IPFS:  https://python.plainenglish.io/how-i-made-my-django-app-faster-and-safer-with-infura-ipfs-94ee149277be - although super-lightweight


### Some GPT Django justification stuff

### Robust Feature Set and Scalability

Django offers a robust suite of features that are essential for developing complex web applications. It includes an ORM (Object-Relational Mapping) for database interactions, a templating engine, form handling, and a powerful admin interface out-of-the-box. These features significantly reduce the amount of boilerplate code, allowing developers to focus on the unique aspects of their application. Additionally, Django's modular architecture supports scalability, allowing the application to handle increased loads as user demand grows. According to Django’s official documentation, the framework is designed to "help developers take applications from concept to completion as quickly as possible"​ ([ethereum.org](https://ethereum.org/en/developers/docs/apis/backend/))​.

### Security and Compliance

Security is paramount in a project that involves sensitive user data and blockchain interactions. Django provides several built-in security features such as protection against SQL injection, cross-site scripting (XSS), cross-site request forgery (CSRF), and clickjacking. These features are essential for ensuring that the application complies with security best practices and protects user data from common web vulnerabilities. Furthermore, Django’s security model includes a robust user authentication system, which can be seamlessly integrated with JWT (JSON Web Token) for secure token-based authentication.

Given the project's future integration plans with asymmetric encryption and IPFS, Django’s flexibility in handling third-party libraries is crucial. The Python ecosystem offers powerful encryption libraries such as `cryptography` and seamless IPFS integration through libraries like `ipfshttpclient`. These tools can be easily incorporated into a Django project, providing secure data storage and management capabilities. According to a study by the Python Software Foundation, Python’s extensive libraries and frameworks are highly favored for their reliability and ease of integration in complex applications​ ([ethereum.org](https://ethereum.org/en/developers/docs/apis/backend/))​.

### Ease of Integration and Community Support

Django’s extensive documentation and large community support further justify its selection for this project. The framework’s comprehensive documentation provides detailed guides and best practices for integrating various functionalities, including advanced security features and third-party integrations. This is particularly beneficial for ensuring the implementation of encryption and decentralized storage solutions are both efficient and secure. Moreover, Django’s active community provides a wealth of plugins and extensions that can further enhance the application's capabilities.

In comparison to other frameworks, Django stands out for its “batteries-included” philosophy. While frameworks like Flask offer simplicity and flexibility, they often require additional setup and integration of third-party tools to achieve the same level of functionality provided by Django out-of-the-box. On the other hand, Node.js-based frameworks like Express.js offer non-blocking, event-driven architecture suitable for handling concurrent operations, but they often lack the robust security features and comprehensive toolset inherent to Django​ ([ethereum.org](https://ethereum.org/en/developers/docs/apis/backend/))​.

### Future-Proofing with Modern Technologies

The project's future direction, including the incorporation of asymmetric encryption and IPFS for decentralized data storage, aligns well with Django’s capabilities. Asymmetric encryption ensures that user data is securely stored and transmitted, protecting it from unauthorized access. IPFS integration further enhances this by providing a decentralized storage solution, ensuring data integrity and availability while complying with GDPR by enabling users to control their data.

In conclusion, Django’s robust feature set, emphasis on security, ease of integration, and strong community support make it the optimal choice for the backend of this decentralized application. Its ability to handle future enhancements with encryption and decentralized storage further solidifies its suitability, ensuring the project remains scalable, secure, and compliant with regulatory standards. This comprehensive approach not only supports the current project requirements but also ensures its long-term viability and security in the evolving landscape of cybersecurity and decentralized applications.
