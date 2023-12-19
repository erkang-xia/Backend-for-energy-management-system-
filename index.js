import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
const app = express();

app.use(express.json());
app.use(cookieParser());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '990724',
  database: 'SHEMS',
});

app.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true,
  })
);

const createToken = (id) => {
  return jwt.sign({ id }, 'sgbvjlxicugyvds', {
    expiresIn: '1h',
  });
};

const verifyToken = (req, res, next) => {
  // const authHeader = req.headers.authorization;
  const authHeader = req.cookies.jwt;
  if (authHeader) {
    const token = authHeader;
    jwt.verify(token, 'sgbvjlxicugyvds', (err, user) => {
      if (err) {
        return res.sendStatus(403); // Forbidden
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401); // Unauthorized
  }
};

app.get('/', (req, res) => {
  res.json('hello this is backend');
});

app.get('/cookie', (req, res) => {
  res.cookie('auth', '123', {
    httpOnly: true,
  });
  res.send('Cookie set');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log(email);
  console.log(password);

  // Query user from the database
  db.query(
    'SELECT * FROM Auth WHERE Email = ?',
    [email],
    async (err, results) => {
      if (err) {
        return res
          .status(500)
          .json({ message: 'Error querying the database', err: true });
      }
      if (results.length === 0) {
        return res.json({ message: 'Email Not Found', err: true });
      }
      const user = results[0];
      console.log(user);

      // Compare password with hashed password in database
      const validPassword = await bcrypt.compare(password, user.Password);

      if (!validPassword) {
        console.log('Incorrect password');
        return res.json({ message: 'Password Incorrect', err: true });
      }

      console.log('verified');

      // Generate JWT
      const token = createToken(user.CustomerID);
      res.cookie('jwt', token, {
        httpOnly: true,
      });
      res.json({ message: 'Cookie set', err: false });
    }
  );
});

// app.post('/signup', async (req, res) => {
//   const { firstName, lastName, address, email, password } = req.body;
//   const salt = await bcrypt.genSalt();
//   let hashedPassword = await bcrypt.hash(password, salt);

//   const createCustomer =
//     'INSERT INTO Customer (Name, BillingAddress) VALUES (?)';
//   const customerInfo = [`${firstName} ${lastName}`, address];

//   // Wrap db.query in a Promise for proper async handling
//   try {
//     // Insert into Customer and wait for it to finish
//     await new Promise((resolve, reject) => {
//       db.query(createCustomer, [customerInfo], (err, data) => {
//         if (err) reject(err);
//         else resolve(data);
//       });
//     });

//     // Get the last inserted ID and wait for it to finish
//     const customerID = await new Promise((resolve, reject) => {
//       db.query('SELECT LAST_INSERT_ID() as id;', (err, data) => {
//         if (err) reject(err);
//         else resolve(data[0].id);
//       });
//     });
//     const token = createToken(customerID);
//     // Insert into Auth
//     const createAuth =
//       'INSERT INTO Auth (Email, Password, CustomerID) VALUES (?)';
//     const authInfo = [email, hashedPassword, customerID];

//     await new Promise((resolve, reject) => {
//       db.query(createAuth, [authInfo], (err, data) => {
//         if (err) reject(err);
//         else resolve(data);
//       });
//     });

//     res
//       .status(200)
//       .json({ message: 'User registered successfully', token: token });
//   } catch (err) {
//     res.status(500).json({ error: 'Internal server error' });
//   }
// });
app.post('/signup', async (req, res) => {
  const { firstName, lastName, address, email, password } = req.body;

  const salt = await bcrypt.genSalt();
  const hashedPassword = await bcrypt.hash(password, salt);

  const createCustomer =
    'INSERT INTO Customer (Name, BillingAddress) VALUES (?)';
  const customerInfo = [`${firstName} ${lastName}`, address];

  db.beginTransaction((err) => {
    if (err) {
      return res.status(500).json({ error: 'Transaction start failed' });
    }

    db.query(createCustomer, [customerInfo], (err, data) => {
      if (err) {
        return db.rollback(() => {
          res.status(500).json({ error: 'Error creating customer' });
        });
      }

      const customerID = data.insertId;
      const createAuth =
        'INSERT INTO Auth (Email, Password, CustomerID) VALUES (?)';
      const authInfo = [email, hashedPassword, customerID];

      db.query(createAuth, [authInfo], (err, data) => {
        if (err) {
          return db.rollback(() => {
            res.status(500).json({ error: 'Error creating auth' });
          });
        }

        db.commit((err) => {
          if (err) {
            return db.rollback(() => {
              res.status(500).json({ error: 'Transaction commit failed' });
            });
          }

          const token = createToken(customerID);
          res.cookie('jwt', token, {
            httpOnly: true,
          });
          res.json({ message: 'Cookie set Rigisration ok', err: false });
        });
      });
    });
  });
});

app.get('/dashboard', verifyToken, (req, res) => {
  const customerId = req.user.id; // Extracted from JWT

  const query = `SELECT 
  sl.LocationID, 
  sl.Address, 
  sl.SquareFootage, 
  sl.NumberOfBedrooms, 
  sl.NumberOfOccupants, 
  sl.ZipCode, 
  d.DeviceID, 
  d.Type, 
  d.ModelNumber
FROM 
  ServiceLocation sl
LEFT JOIN 
  Device d ON sl.LocationID = d.LocationID
WHERE 
  sl.CustomerID = ?;`;

  db.query(query, [customerId], (err, results) => {
    if (err) {
      return res
        .status(500)
        .json({ message: 'Error querying the database', error: err });
    }
    // Process results and format them as needed for the frontend
    res.json(results);
  });
});

app.get('/location/:location_id', verifyToken, (req, res) => {
  const locationId = req.params.location_id;
  const q = `SELECT 
  DATE_FORMAT(E.Timestamp, '%H:00') AS Hour,
  SUM(E.EnergyConsumed) AS TotalEnergyConsumed
FROM 
  EnergyUsage E
INNER JOIN 
  Device D ON E.DeviceID = D.DeviceID
WHERE 
  D.LocationID = ? 
  AND DATE(E.Timestamp) = '2022-12-11'
GROUP BY 
  DATE_FORMAT(E.Timestamp, '%H:00')
  ORDER BY 
    DATE_FORMAT(E.Timestamp, '%H:00') ASC;
`;
  db.query(q, [locationId], (err, data) => {
    if (err) {
      return res.json('There is error access the informatioon' + err);
    }

    return res.json(data);
  });
});

app.get('/device_event', verifyToken, (req, res) => {
  const customerId = req.user.id; // Extracted from JWT
  const q = `SELECT 
  DE.EventID,
  DE.DeviceID,
  DE.Timestamp,
  DE.EventType,
  DE.EventValue
FROM 
  Customer C
JOIN 
  ServiceLocation SL ON C.CustomerID = SL.CustomerID
JOIN 
  Device D ON SL.LocationID = D.LocationID
JOIN 
  DeviceEvent DE ON D.DeviceID = DE.DeviceID
WHERE 
  C.CustomerID = ?; -- Replace with the actual CustomerID

`;
  db.query(q, [customerId], (err, data) => {
    if (err) {
      return res.json('There is error access the informatioon' + err);
    }

    return res.json(data);
  });
});

app.get('/device_type_event/:location_id', verifyToken, (req, res) => {
  const customerId = req.user.id; // Extracted from JWT
  const locationId = req.params.location_id;

  const q = `SELECT 
  D.Type AS ApplianceType,
  SUM(EU.EnergyConsumed) AS TotalEnergyConsumed
FROM 
  EnergyUsage EU
JOIN 
  Device D ON EU.DeviceID = D.DeviceID
JOIN 
  ServiceLocation SL ON D.LocationID = SL.LocationID
WHERE 
  SL.CustomerID = ?
  AND SL.LocationID = ?
  AND MONTH(EU.Timestamp) = 12
  AND YEAR(EU.Timestamp) = 2022
GROUP BY 
  D.Type;

`;
  db.query(q, [customerId, locationId], (err, data) => {
    if (err) {
      return res.json('There is error access the informatioon' + err);
    }

    return res.json(data);
  });
});

app.get('/cost/:location_id', verifyToken, (req, res) => {
  const customerId = req.user.id; // Extracted from JWT
  const locationId = req.params.location_id;

  const q = `SELECT 
  SUM(EU.EnergyConsumed * EP.PricePerKWh) AS TotalCost
FROM 
  EnergyUsage EU
JOIN 
  Device D ON EU.DeviceID = D.DeviceID
JOIN 
  ServiceLocation SL ON D.LocationID = SL.LocationID
JOIN 
  EnergyPrice EP ON SL.ZipCode = EP.ZipCode
WHERE 
  SL.CustomerID = ?
  AND SL.LocationID = ?
  AND MONTH(EU.Timestamp) = 12
  AND YEAR(EU.Timestamp) = 2022
GROUP BY 
  MONTH(EU.Timestamp), YEAR(EU.Timestamp);

`;
  db.query(q, [customerId, locationId], (err, data) => {
    if (err) {
      return res.json('There is error access the informatioon' + err);
    }

    return res.json(data);
  });
});

app.get('/device/:device_id', verifyToken, (req, res) => {
  const device_id = req.params.device_id;

  const q = `SELECT 
  DATE_FORMAT(EU.Timestamp, '%Y-%m-%d') AS Date,
  SUM(EU.EnergyConsumed) AS TotalEnergyConsumed
FROM 
  EnergyUsage EU
WHERE 
  EU.DeviceID = ?
  AND EU.Timestamp >= DATE_FORMAT(NOW() - INTERVAL 1 MONTH, '%Y-%m-01')
GROUP BY 
  DATE_FORMAT(EU.Timestamp, '%Y-%m-%d')
ORDER BY
  Date;
`;
  db.query(q, [device_id], (err, data) => {
    if (err) {
      return res.json('There is error access the informatioon' + err);
    }

    return res.json(data);
  });
});

app.get('/deviceTypeCost/:device_id', verifyToken, (req, res) => {
  const device_id = req.params.device_id;

  const q = `SELECT
  AVG(MonthlyUsage) AS AverageMonthlyConsumption
FROM (
  SELECT
      Device.Type,
      SUM(EnergyUsage.EnergyConsumed) AS MonthlyUsage
  FROM
      Device
  INNER JOIN
      EnergyUsage ON Device.DeviceID = EnergyUsage.DeviceID
  WHERE
      MONTH(EnergyUsage.Timestamp) = MONTH(CURRENT_DATE()) AND
      YEAR(EnergyUsage.Timestamp) = YEAR(CURRENT_DATE()) AND
      Device.Type = (
          SELECT Type FROM Device WHERE DeviceID = ?
      )
  GROUP BY
      Device.DeviceID
) AS MonthlyConsumption

`;
  db.query(q, [device_id], (err, data) => {
    if (err) {
      return res.json('There is error access the informatioon' + err);
    }

    return res.json(data);
  });
});

app.get('/device', verifyToken, (req, res) => {
  const q = 'SELECT * FROM Device';
  db.query(q, (err, data) => {
    if (err) {
      return res.json('There is error access the informatioon' + err);
    }

    return res.json(data);
  });
});

app.post('/device', verifyToken, (req, res) => {
  const q = 'INSERT INTO Device ( LocationID, Type, ModelNumber) VALUES (?)';
  const VALUES = [req.body.LocationID, req.body.Type, req.body.ModelNumber];

  db.query(q, [VALUES], (err, data) => {
    if (err) return res.json(err);
    return res.json('success');
  });
});

app.post('/removeDevice', verifyToken, (req, res) => {
  const q =
    'DELETE FROM Device WHERE LocationID = ? AND Type = ? AND ModelNumber = ? ';
  const loca = req.body.LocationID;
  const type = req.body.Type;
  const model = req.body.ModelNumber;
  db.query(q, [loca, type, model], (err, data) => {
    if (err) return res.json(err);
    return res.json('success');
  });
});

app.post('/removeDevicebyId', verifyToken, (req, res) => {
  const q = 'DELETE FROM Device WHERE DeviceID = ? ';
  const id = req.body.DeviceID;
  db.query(q, [id], (err, data) => {
    if (err) return res.json(err);
    return res.json('success');
  });
});

app.post('/addLocation', verifyToken, (req, res) => {
  const customerId = req.user.id;
  const q =
    'INSERT INTO ServiceLocation ( ZipCode, CustomerID, Address, SquareFootage, NumberOfBedrooms, NumberOfOccupants) VALUES (?)';
  const VALUES = [
    req.body.ZipCode,
    customerId,
    req.body.Address,
    req.body.SquareFootage,
    req.body.NumberOfBedrooms,
    req.body.NumberOfOccupants,
  ];

  db.query(q, [VALUES], (err, data) => {
    if (err) return res.json(err);
    return res.json('success');
  });
});

app.post('/removeAll', verifyToken, (req, res) => {
  const q = `WITH LocationToDelete AS (
      SELECT LocationID
      FROM ServiceLocation
      WHERE CustomerID = ? AND Address = ?
  )
  DELETE FROM Device
  WHERE LocationID IN (SELECT LocationID FROM LocationToDelete);`;
  const customerId = req.user.id;
  const address = req.body.Address;
  db.query(q, [customerId, address], (err, data) => {
    if (err) return res.json(err);
    return res.json('success');
  });
});
app.post('/removeLocation', verifyToken, async (req, res) => {
  const customerId = req.user.id;
  const address = req.body.Address;

  const q = ` 
  WITH LocationToDelete AS (
    SELECT LocationID
    FROM ServiceLocation
    WHERE CustomerID = ? AND Address = ?
)
DELETE FROM ServiceLocation
WHERE LocationID IN (SELECT LocationID FROM LocationToDelete);`;

  db.query(q, [customerId, address], (err, data) => {
    if (err) return res.json(err);
    return res.json('success');
  });
});

app.post('/removeLocation', verifyToken, async (req, res) => {
  const customerId = req.user.id;
  const address = req.body.Address;

  const q = ` 
  WITH LocationToDelete AS (
    SELECT LocationID
    FROM ServiceLocation
    WHERE CustomerID = ? AND Address = ?
)
DELETE FROM ServiceLocation
WHERE LocationID IN (SELECT LocationID FROM LocationToDelete);`;

  db.query(q, [customerId, address], (err, data) => {
    if (err) return res.json(err);
    return res.json('success');
  });
});

app.listen(8800, () => {
  console.log('connected to backend!');
});
