const express = require('express');
const app = express();
const SSLCommerzPayment = require('sslcommerz-lts')
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

const store_id = process.env.STORE_ID;
const store_passwd = process.env.STORE_PASS;
const is_live = false;


async function run() {
    try {
        const userCollections = client.db("Bus-Ticket").collection('users');
        const orderCollections = client.db("Bus-Ticket").collection('orders');
        const allocatedSeatCollections = client.db("Bus-Ticket").collection('allocatedSeat');

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

        app.post('/payment', async (req, res) => {
            const price = req.body.price;
            const name = req.body.name;
            const email = req.body.email;
            const location = req.body.location;
            const address = req.body.address;
            const phone = req.body.phone;
            const allocatedSeat = req.body.allocatedSeat;

            const tran_id = new ObjectId().toString();
            const data = {
                total_amount: price,
                currency: 'BDT',
                tran_id: tran_id,
                success_url: `http://localhost:5000/payment/success/${tran_id}`,
                fail_url: `http://localhost:5000/payment/fail/${tran_id}`,
                cancel_url: 'http://localhost:3030/cancel',
                ipn_url: 'http://localhost:3030/ipn',
                shipping_method: 'Courier',
                product_name: 'Computer.',
                product_category: 'Electronic',
                product_profile: 'general',
                cus_name: name,
                cus_email: email,
                cus_add1: address,
                cus_add2: 'Dhaka',
                cus_city: 'Dhaka',
                cus_state: 'Dhaka',
                cus_postcode: '1000',
                cus_country: 'Bangladesh',
                cus_phone: phone,
                cus_fax: '01711111111',
                ship_name: 'Customer Name',
                ship_add1: 'Dhaka',
                ship_add2: 'Dhaka',
                ship_city: 'Dhaka',
                ship_state: 'Dhaka',
                ship_postcode: 1000,
                ship_country: 'Bangladesh',
                location: location,
                allocatedSeat: allocatedSeat
            };

            const sslcz = new SSLCommerzPayment(store_id, store_passwd, is_live);
            sslcz.init(data).then(apiResponse => {
                // console.log('API Response:', apiResponse); // Log full response for debugging
                if (apiResponse.GatewayPageURL) {
                    // Redirect the user to payment gateway
                    let GatewayPageURL = apiResponse.GatewayPageURL;
                    res.send({ url: GatewayPageURL });

                    const order = {
                        price: price,
                        name: name,
                        phone: phone,
                        email: email,
                        location: location,
                        address: address,
                        allocatedSeat: allocatedSeat,
                        tran_id: tran_id,
                        status: 'loading'
                    }
                    const seat = {
                        allocatedSeat: allocatedSeat,
                        status: 'loading',
                        tran_id: tran_id,
                    }

                    const result = orderCollections.insertOne(order);
                    console.log(result)
                    const blockedSeat = allocatedSeatCollections.insertOne(seat);
                    console.log(blockedSeat)


                    console.log('Redirecting to: ', GatewayPageURL);
                } else {
                    res.status(400).send({ error: 'Failed to get GatewayPageURL', details: apiResponse });
                }
            }).catch(error => {
                console.error('SSLCommerz API Error:', error);
                res.status(500).send({ error: 'Payment initialization failed', details: error });
            });
        });

        // payment success 
        app.post('/payment/success/:tran_id', async (req, res) => {
            console.log(req.params.tran_id);
            const result = await orderCollections.updateOne(
                { tran_id: req.params.tran_id },
                {
                    $set: { status: 'paid' }
                }
            )
            const success = await allocatedSeatCollections.updateOne(
                { tran_id: req.params.tran_id },
                {
                    $set: { status: 'paid' }
                }
            )
            if (result.modifiedCount > 0) {
                res.redirect(`http://localhost:5173/payment/success/${req.params.tran_id}`)
            }
        })


        //payment fail
        app.post('/payment/fail/:tran_id', async (req, res) => {
            const result = await orderCollections.deleteOne(
                { tran_id: req.params.tran_id }
            );

            const seat = await allocatedSeatCollections.deleteOne(
                { tran_id: req.params.tran_id }
            );

            if (result.deletedCount > 0 && seat.deletedCount > 0) {
                res.redirect(`http://localhost:5173/payment/fail/${req.params.tran_id}`);
            } else {
                res.status(500).send({ message: 'Failed to delete order or seat data' });
            }
        });
        // Get allocated seats with status 'paid'
        app.get('/allocated-seats', verifyJWT, async (req, res) => {
            try {
                const paidSeats = await allocatedSeatCollections.find({ status: 'paid' }).toArray();
                res.status(200).send(paidSeats);
            } catch (error) {
                res.status(500).send({ message: 'Error fetching allocated seats', error });
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
