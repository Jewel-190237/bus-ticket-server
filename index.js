const express = require('express');
const app = express();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const PORT = process.env.PORT || 5000;

// MiddleWare
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.kwtddbl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// JWT Authentication Middleware
const verifyJWT = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized access' });
    }

    jwt.verify(token.split(' ')[1], process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send({ message: 'Forbidden access' });
        }
        req.user = decoded;
        next();
    });
};

// Admin Role Middleware
const verifyAdmin = async (req, res, next) => {
    const user = await client.db("Bus-Ticket").collection('users').findOne({ _id: new ObjectId(req.user.id) });
    if (user && user.role === 'admin') {
        next(); // If admin, proceed to the route
    } else {
        res.status(403).send({ message: 'Admin access required' });
    }
};

async function run() {
    try {
        const userCollections = client.db("Bus-Ticket").collection('users');

        // Create user (sign-up)
        app.post('/users', async (req, res) => {
            const user = req.body;
            const query = { phone: user.phone };
            const existingUser = await userCollections.findOne(query);

            if (existingUser) {
                return res.status(409).send({ message: 'User already exists. Please login.' });
            }

            const result = await userCollections.insertOne(user);
            res.status(200).send(result);
        });

        // Login
        app.post('/login', async (req, res) => {
            const { phone, password, role } = req.body;

            try {
                // Find the user by phone number
                const user = await userCollections.findOne({ phone });
                if (!user) {
                    return res.status(402).send({ message: 'User not found' });
                }

                if (user.role !== role) {
                    return res.status(403).send({ message: 'Access denied. Role does not match.' });
                }

                // Check if the password matches
                if (password !== user.password) {
                    return res.status(401).send({ message: 'Invalid password' });
                }

                const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
                res.status(200).send({ message: 'Login successful', token });
            } catch (error) {
                res.status(500).send({ message: 'Login failed', error });
            }
        });

        // Protected route for admin users
        app.get('/admin/dashboard', verifyJWT, verifyAdmin, (req, res) => {
            res.status(200).send({ message: 'Welcome Admin to the dashboard' });
        });

        // Check user authentication status
        app.get('/auth-status', verifyJWT, async (req, res) => {
            res.status(200).send({ isLoggedIn: true, role: req.user.role });
        });

        // get all users
        app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
            const user = userCollections.find();
            const result = await user.toArray();
            res.send(result);
        })
        // delete a specific user
        app.delete('/users/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            console.log('Deleting user with ID:', id);  
            const query = { _id: new ObjectId(id) };
            const result = await userCollections.deleteOne(query);
            res.send(result);
        })

        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('bus-ticket is running');
})

app.listen(PORT, () => {
    console.log(`bus-ticket is running on ${PORT}`);
});
