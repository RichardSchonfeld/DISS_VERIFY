
1. Data collected into JSON object on signup
2. A file is created, write JSON to file
3. Pass file to DB
4. Get file hash (location)
5. Store hash in the Eth contract

Validation:
1. User visits website
2. web3js gets active Eth account
3. Read from the user contract to find the associated hash
4. Get file
5. Read the JSON object
6. Extract the data from the JSON
7. Display data to user