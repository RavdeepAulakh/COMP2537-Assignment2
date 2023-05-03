
// require("../utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

// const port = process.env.PORT || 3000;

const app = express();
app.set('view engine', 'ejs');

const Joi = require("joi");


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const {MONGODB_HOST,
    MONGODB_USER,
    MONGODB_PASSWORD,
    MONGODB_DATABASE,
    MONGODB_SESSION_SECRET,
    NODE_SESSION_SECRET} = process.env;


/* END secret section */

const database = require("../databaseConnection.js");

const userCollection = database.db(MONGODB_DATABASE).collection('users');

app.use(express.urlencoded({extended: false}));
app.use(express.static(__dirname + "/../views"));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${MONGODB_USER}:${MONGODB_PASSWORD}@${MONGODB_HOST}/test`,
	crypto: {
		secret: MONGODB_SESSION_SECRET
	}
})

app.use(session({ 
    secret: NODE_SESSION_SECRET,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {message: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}


app.get('/', (req,res) => {
    if (req.session.authenticated){
        res.redirect('/loggedin');
        return;
    }
    res.render("index");
  });
  

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.render("errorMessage", {message: `no user provided - try /nosql-injection?user=name or /nosql-injection?user[$ne]=name`});
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.render("errorMessage", {message: 'A NoSQL injection attack was detected!!'});
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.render("hellomessage", {username: username})
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.render("about", {color: color})
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    res.render("contact", {missing: missingEmail});
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.render("submitEmail", {email: email});
    }
});


app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1, user_type: 1, email: 1, _id: 1}).toArray();
 
    res.render("admin", {users: result});
});

// Promote user to admin
app.post('/admin/promote', async (req, res) => {
    const email = req.body.email;

    try {
      // Update the user's user_type in the database
      await userCollection.updateOne({ email: email }, { $set: { user_type: 'admin' } });
      console.log('User promoted to admin:', email);
      res.redirect('/admin');
    } catch (error) {
      console.error('Error promoting user:', error);
      res.redirect('/admin');
    }
  });
  
  // Demote admin to user
  app.post('/admin/demote', async (req, res) => {
    const email = req.body.email;
    
    try {
      // Update the user's user_type in the database
      await userCollection.updateOne({ email: email }, { $set: { user_type: 'user' } });
      console.log('Admin demoted to user:', email);
      res.redirect('/admin');
    } catch (error) {
      console.error('Error demoting admin:', error);
      res.redirect('/admin');
    }
  });
  

app.get('/createUser', (req,res) => {
    res.render("createUser");
});


app.get('/login', (req,res) => {
    res.render("login");
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

    if (!email){
        return res.render("submitError", {message: "Email cannot be blank"});
    }
    if(!password){
        return res.render("submitError", {message: "Password cannot be blank"});
    }
    if(!username){
        return res.render("submitError", {message: "Username cannot be blank"});
    }
	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, password, email});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/createUser");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, password: hashedPassword, email: email});
	console.log("Inserted user");
    req.session.username = username;
    req.session.authenticated = true;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/loggedin');
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;
	const schema = Joi.string().email().required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({username: 1, password: 1, user_type: 1, _id: 1}).toArray();
    const username = result[0].username;

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.username = username;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedin');
		return;
	}
	else {
		return res.render("loginfail");
	}
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    res.render("loggedin", {user: req.session.username});
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});


app.get('/cat/:id', (req,res) => {

    var cat = req.params.id;

    res.render("cat", {cat: cat});
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

// app.listen(port, () => {
// 	console.log("Node application listening on port "+port);
// }); 

module.exports = app;