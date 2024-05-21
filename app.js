const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
//to hash the password
const bcrypt = require('bcrypt');
//to read the users.json
const fs = require('fs');
//import the function from generate-token.js to generate the token
const generateJWT = require('./generate-token');

const app = express();

const PORT = 3000;

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(bodyParser.urlencoded( {extended: true}));
app.use(cookieParser());






//server secret used to generate the token
const jwtSecret = 'OurSecretKey';


//Token verification middleware
const authenticateJWT = (req, res, next) => {
    console.log("Beginning Validation...");

     // Extract the JWT token from the Cookie header
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) {
        // If the Cookie header is missing, return the user to the login page
        const returnUrl = encodeURIComponent(req.originalUrl);
        return res.redirect(`/account/login-page?returnUrl=${returnUrl}`);
    }

    // Extract the token value from the Cookie header
    const cookies = cookieHeader.split(';').map(cookie => cookie.trim());
    const accessTokenCookie = cookies.find(cookie => cookie.startsWith('accessToken='));
    if (!accessTokenCookie) {
        //if theres no token re-direct to the login page
        const returnUrl = encodeURIComponent(req.originalUrl);
        return res.redirect(`/account/login-page?returnUrl=${returnUrl}`);
    }

    const token = accessTokenCookie.split('=')[1];

    
    //print the token for debugging
    //console.log("Extracted token:", token);

    //verify the token 
    jwt.verify(token, jwtSecret, (err, user) =>{
        if(err) return res.sendStatus(403);
        req.user = user;
        console.log("Ending Validation");
        next();
    
    });

};

/* A NOTE ON THE USERS  
I am commenting out the users here so that I can keep them in a seperate file, this will show you that when you submit the form a new user will be added
Look for the file users.json, in the same directory 

const users = [
    {id: 1, username: "user1", password: "password1"}
];
*/
    // make a local users array to hold the data from the users.json file
    // we are using the readFileSync from previous labs to do this
    // it is in a try catch just incase there is an error reading the file 
    let users = [];
    try {
        const data = fs.readFileSync('users.json', 'utf8');
        users = JSON.parse(data);
    } catch (err) {
        console.error("Error reading users file:", err);
    }




// account routes 
// login
app.get('/account/login-page', (req, res) => {
    //define the returnUrl if the user is sent here by middleware
    const returnUrl = req.query.returnUrl || '/home'; // Default to '/home' if returnUrl is not provided
    //read the login-page.html file
    fs.readFile(path.join(__dirname, 'login-page.html'), 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading login-page.html:', err);
            return res.status(500).send('Internal Server Error');
        }
        //change the placeholder in the login-page.html so that it holds the returnURL
        const modifiedHtml = data.replace('RETURN_URL_PLACEHOLDER', returnUrl);
        res.send(modifiedHtml);
});
});

        //login submission
app.post('/account/login', async (req, res) => {
    const { username, password, returnUrl} = req.body;
    // Check if the user exists
    const user = users.find(user => user.username === username);

    // if they don't exist return an error
    if (!user) {
        return res.status(401).send("invalid username");
    }

    try {
        // Compare passwords using bcrypt
        const passwordMatch = await bcrypt.compare(password, user.hashedPassword);

        // if the passwords don't match return an error
        if (!passwordMatch) {
            return res.status(401).send('invalid password');
        }
        


        // Passwords match, generate a webtoken for the user
        const token = generateJWT({ username: user.username }, jwtSecret);

        //print the token for debug
        //console.log("Generated token:", token);

        // Set token as a session cookie with httponly and secure flags
        res.cookie('accessToken', token, { httpOnly: true, secure: false });

        // Read the return url from the login-page.html, if it doesn't exist redirect to /home

        if (returnUrl) {
            res.redirect(returnUrl);
        } else {
            res.redirect('/home');
        }
    } catch (error) {
        //catch an error if the password comparing goes wrong
        console.error("Error comparing passwords:", error);
        res.status(500).send('something is horribly wrong');
    }
});



//sign-up-page
app.get('/account/sign-up-page',  (req, res) => {
    res.sendFile(path.join(__dirname, '/sign-up-page.html'));
});
//sign-up form submission
app.post('/account/sign-up', async (req, res) => {
      const { username, password } = req.body; 


    // check if the user exists
     const userExists = users.some(user => user.username === username);

    if (userExists) {
        return res.status(400).json({ error: "Username already exists" });
    }
    // if the user doesn't exist we can add them to users.json
    // this is in a try catch block, in case the file writing fails
      try {
        // salt and hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Add the new user to the users array
        const newUser = { id: users.length + 1, username, hashedPassword };
        users.push(newUser);

        // Write the updated users data back to the JSON file
          //fs.writefilesync is a method we previously used in class to write data to a file on the server I'm doing it this way so you can see the users.json file update when the form is submitted
          // we are using the stringify method to turn the users array we just made into json for the users.json file, the (users, null, 2) means take users array, null means don't transform it, the 2 means that we'll have 2 spaces of indentation to make it easier to read
        fs.writeFileSync('users.json', JSON.stringify(users, null, 2));

        // if the user sign-up is successful then send the user to the login-page
        res.redirect('/account/login-page');
    } catch (error) {
        //this catch error will let us know if something goes wrong with writing to users.json
        console.error("Error creating user:", error);
        res.status(500).send('Something is horribly wrong');
    }
});

//regular routes
app.get('/home', authenticateJWT, (req, res) => {
    // Adding a button to logout
    const logoutButton = '<a href="/account/logout">Logout</a>';
    res.send(`<html><body> <h1> Home! </h1> ${logoutButton}</body> </html>`);
    
});
app.get('/about', authenticateJWT, (req, res) => {
    // Adding a button to logout
    const logoutButton = '<a href="/account/logout">Logout</a>';
    res.send(`<html><body> <h1>  About! </h1> ${logoutButton}</body> </html>`);
});
app.get('/contact', authenticateJWT, (req, res) => {
    // Adding a button to logout
    const logoutButton = '<a href="/account/logout">Logout</a>';
    res.send(`<html><body> <h1> Contact! </h1> ${logoutButton}</body> </html>`);
});

//logout route 
app.get('/account/logout', (req, res) => {
    // Clear the session cookie containing the JWT
    res.clearCookie('accessToken');

    // Redirect the user to the login page
    res.redirect('/account/login-page');
});


app.listen(PORT,() =>
    console.log(`Listening on port ${PORT}`));