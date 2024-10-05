const express = require('express');
const app = express();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const PORT = process.env.PORT || 5000;
const nodemailer = require('nodemailer');

// MiddleWare
app.use(cors());
app.use(express.json());

// JWT Authentication Middleware
const verifyJWT = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized access' });
    }

    const tokenWithoutBearer = token.split(' ')[1];
    console.log('JWT Token:', tokenWithoutBearer); // Debug

    jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send({ message: 'Forbidden access' });
        }
        console.log('Decoded JWT:', decoded); // Debug
        req.user = decoded;
        next();
    });
};

// Admin Role Middleware
const verifyAdmin = async (req, res, next) => {
    try {
        const user = await client.db("Bus-Ticket").collection('users').findOne({ _id: new ObjectId(req.user.id) });
        console.log('User Role:', user.role); // Debug
        if (user && user.role === 'admin') {
            next();
        } else {
            res.status(403).send({ message: 'Admin access required' });
        }
    } catch (error) {
        res.status(500).send({ message: 'Error verifying admin role', error });
    }
};


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.kwtddbl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});


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
                userToken = token;
                res.status(200).send({ message: 'Login successful', token });
            } catch (error) {
                res.status(500).send({ message: 'Login failed', error });
            }
        });

        // Check user authentication status
        app.get('/auth-status', verifyJWT, async (req, res) => {
            res.status(200).send({ isLoggedIn: true, role: req.user.role });
        });

        // Get all users (admin-only access)
        app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const user = userCollections.find();
                const result = await user.toArray();
                res.status(200).send(result);
            } catch (error) {
                res.status(500).send({ message: 'Error fetching users', error });
            }
        });

        // Delete a specific user (admin-only access)
        app.delete('/users/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            console.log('Deleting user with ID:', id);
            const query = { _id: new ObjectId(id) };
            try {
                const result = await userCollections.deleteOne(query);
                if (result.deletedCount === 1) {
                    res.status(200).send({ message: 'User deleted successfully' });
                } else {
                    res.status(404).send({ message: 'User not found' });
                }
            } catch (error) {
                res.status(500).send({ message: 'Error deleting user', error });
            }
        });


        // email verification
        app.post('/forgetPassword', async (req, res) => {
            const { phone, email } = req.body;

            try {
                const existingUser = await userCollections.findOne({ phone });

                if (!existingUser) {
                    return res.status(404).send({ message: 'User not found' });
                }

                //sent email
                var transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: '190237@ku.ac.bd',
                        pass: 'afio mvyu nrrc urkv'
                    }
                });
                const token = jwt.sign({ id: existingUser._id, role: existingUser.role }, process.env.JWT_SECRET, { expiresIn: '5m' });
                var mailOptions = {
                    from: '190237@ku.ac.bd',
                    to: email,
                    subject: 'Reset Password',
                    text: `http://localhost:5173/resetPassword/${token}`
                };

                transporter.sendMail(mailOptions, function (error, info) {
                    if (error) {
                        console.log(error);
                    } else {
                        console.log('Email sent: ' + info.response);
                    }
                });

                res.status(200).send({ message: 'User found', email: email });
            } catch (error) {
                res.status(500).send({ message: 'Error while searching for user', error });
            }
        });

        // reset password
        app.post('/resetPassword', async (req, res) => {
            const { token, newPassword } = req.body;

            try {
                jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
                    if (err) {
                        return res.status(400).send({ message: 'Invalid or expired token' });
                    }

                    const user = await userCollections.findOne({ _id: new ObjectId(decoded.id) });

                    if (!user) {
                        return res.status(404).send({ message: 'User not found' });
                    }

                    const result = await userCollections.updateOne(
                        { _id: new ObjectId(user._id) },
                        { $set: { password: newPassword } }
                    );

                    if (result.modifiedCount === 1) {
                        return res.status(200).send({ message: 'Password updated successfully' });
                    } else {
                        return res.status(500).send({ message: 'Failed to update password' });
                    }
                });
            } catch (error) {
                res.status(500).send({ message: 'Error while resetting password', error });
            }
        });


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
