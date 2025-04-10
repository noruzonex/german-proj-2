// index.js

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(cors({ origin: '*' })); // Allow all origins for development
app.use(express.json());

// Create a MySQL connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'root',  // Change to your MySQL password
  database: 'germanllm',  // Ensure this database exists
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// JWT secret – store securely in production
const JWT_SECRET = 'secretKey';

// Helper function: Shuffle array and return first n items
function getRandomSubset(arr, n) {
  let shuffled = arr.slice();
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled.slice(0, n);
}

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

/* *********************** 
   USER REGISTRATION
*********************** */
app.post(
  '/api/register',
  // Validation middleware
  [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email address'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters long')
  ],
  async (req, res) => {
    // Validate data
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res
        .status(400)
        .json({ error: 'Validation failed', details: errors.array() });
    const { name, email, password } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const sql =
        'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
      await pool.execute(sql, [name, email, hashedPassword]);
      res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
      console.error('Registration error:', err);
      res.status(400).json({ error: 'Registration failed', details: err.message });
    }
  }
);

/* *********************** 
   USER LOGIN
*********************** */
app.post(
  '/api/login',
  // Validation middleware
  [
    body('email').isEmail().withMessage('Invalid email address'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  async (req, res) => {
    // Validate inputs
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res
        .status(400)
        .json({ error: 'Validation failed', details: errors.array() });
    const { email, password } = req.body;
    try {
      const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
      if (rows.length === 0)
        return res.status(400).json({ error: 'Invalid credentials' });
      const user = rows[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch)
        return res.status(400).json({ error: 'Invalid credentials' });
      const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } catch (err) {
      console.error('Error during login:', err);
      res.status(500).json({ error: 'Server error during login' });
    }
  }
);

/* *********************** 
   GET ALL LESSONS
*********************** */
app.get('/api/lessons', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM lessons');
    res.json(rows);
  } catch (err) {
    console.error('Error fetching lessons:', err);
    res.status(500).json({ error: 'Failed to fetch lessons' });
  }
});

/* *********************** 
   GET SPECIFIC LESSON BY ID
*********************** */
app.get('/api/lesson/:id', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM lessons WHERE id = ?', [req.params.id]);
    if (rows.length === 0)
      return res.status(404).json({ error: 'Lesson not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching lesson:', err);
    res.status(500).json({ error: 'Failed to fetch lesson' });
  }
});

/* *********************** 
   CREATE NEW LESSON
*********************** */
app.post(
  '/api/lessons',
  // Data validation
  [
    body('title').notEmpty().withMessage('Title is required'),
    body('level').notEmpty().withMessage('Level is required'),
    body('description').notEmpty().withMessage('Description is required'),
    body('content').notEmpty().withMessage('Content is required')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    const { title, level, description, content } = req.body;
    try {
      const [result] = await pool.execute(
        'INSERT INTO lessons (title, level, description, content) VALUES (?, ?, ?, ?)',
        [title, level, description, content]
      );
      const [rows] = await pool.execute('SELECT * FROM lessons WHERE id = ?', [result.insertId]);
      res.status(201).json(rows[0]);
    } catch (err) {
      console.error('Error creating lesson:', err);
      res.status(400).json({ error: 'Failed to create lesson', details: err.message });
    }
  }
);

/* *********************** 
   UPDATE LESSON (e.g., marking as completed)
*********************** */
app.put('/api/lesson/:id', authMiddleware, async (req, res) => {
  const { completed } = req.body;
  try {
    await pool.execute('UPDATE lessons SET completed = ? WHERE id = ?', [completed, req.params.id]);
    const [rows] = await pool.execute('SELECT * FROM lessons WHERE id = ?', [req.params.id]);
    if (rows.length === 0)
      return res.status(404).json({ error: 'Lesson not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Error updating lesson:', err);
    res.status(500).json({ error: 'Failed to update lesson' });
  }
});

/* *********************** 
   UPDATE USER PROGRESS
*********************** */
app.post('/api/progress', authMiddleware, async (req, res) => {
  const { progress } = req.body;
  try {
    await pool.execute('UPDATE users SET progress = ? WHERE id = ?', [JSON.stringify(progress), req.userId]);
    res.json({ message: 'Progress saved successfully' });
  } catch (err) {
    console.error('Error updating progress:', err);
    res.status(500).json({ error: 'Failed to save progress' });
  }
});

/* *********************** 
   QUIZ QUESTIONS ENDPOINTS
*********************** */

/* For "Sich vorstellen" */
const sichVorstellenUniqueQuestions = [
  {
    question: "What does 'Hallo' mean in English?",
    options: ["Hello", "Goodbye", "Please"],
    correct: "Hello"
  },
  {
    question: "How do you say 'My name is...' in German?",
    options: ["Ich heiße...", "Ich bin...", "Ich wohne..."],
    correct: "Ich heiße..."
  },
  {
    question: "What does 'Wie heißt du?' ask?",
    options: ["How old are you?", "What is your name?", "Where do you live?"],
    correct: "What is your name?"
  },
  {
    question: "Which phrase means 'Nice to meet you'?",
    options: ["Schön, dich kennenzulernen", "Auf Wiedersehen", "Guten Tag"],
    correct: "Schön, dich kennenzulernen"
  },
  {
    question: "How do you greet someone in the morning?",
    options: ["Guten Morgen", "Guten Abend", "Gute Nacht"],
    correct: "Guten Morgen"
  },
  {
    question: "Which word means 'Goodbye'?",
    options: ["Hallo", "Auf Wiedersehen", "Tschüss"],
    correct: "Auf Wiedersehen"
  },
  {
    question: "How do you ask someone's name?",
    options: ["Wie geht es dir?", "Wie heißt du?", "Wie alt bist du?"],
    correct: "Wie heißt du?"
  },
  {
    question: "What does 'Ich bin' translate to?",
    options: ["I am", "I have", "I live"],
    correct: "I am"
  },
  {
    question: "Which greeting is used in the afternoon?",
    options: ["Guten Tag", "Guten Morgen", "Guten Abend"],
    correct: "Guten Tag"
  },
  {
    question: "What does 'Auf Wiedersehen' mean?",
    options: ["See you later", "Goodbye", "Hello"],
    correct: "Goodbye"
  },
  {
    question: "Which term is used for informal greetings?",
    options: ["Hi", "Grüß Gott", "Guten Tag"],
    correct: "Hi"
  },
  {
    question: "How do you ask, 'How are you?' in a formal way?",
    options: ["Wie geht es Ihnen?", "Wie geht’s dir?", "Wie heißt du?"],
    correct: "Wie geht es Ihnen?"
  },
  {
    question: "What does 'Mir geht es gut' mean?",
    options: ["I am fine", "I am hungry", "I am tired"],
    correct: "I am fine"
  },
  {
    question: "How do you say 'Thank you' in German?",
    options: ["Danke", "Bitte", "Entschuldigung"],
    correct: "Danke"
  },
  {
    question: "Which phrase is used to greet someone politely?",
    options: ["Guten Tag", "Hi", "Servus"],
    correct: "Guten Tag"
  },
  {
    question: "How do you express 'I live in...'?",
    options: ["Ich wohne in...", "Ich heiße...", "Ich bin..."],
    correct: "Ich wohne in..."
  },
  {
    question: "What is the correct formal farewell?",
    options: ["Auf Wiedersehen", "Tschüss", "Bis dann"],
    correct: "Auf Wiedersehen"
  },
  {
    question: "How do you say 'I am happy to see you'?",
    options: ["Ich freue mich, dich zu sehen", "Ich bin müde", "Ich habe Hunger"],
    correct: "Ich freue mich, dich zu sehen"
  },
  {
    question: "Which question asks about one’s origin?",
    options: ["Woher kommst du?", "Wie alt bist du?", "Wie heißt du?"],
    correct: "Woher kommst du?"
  },
  {
    question: "How do you say 'Nice to meet you' in a formal tone?",
    options: ["Schön, Sie kennenzulernen", "Hallo", "Tschüss"],
    correct: "Schön, Sie kennenzulernen"
  },
  {
    question: "What does 'Guten Abend' mean?",
    options: ["Good evening", "Good morning", "Goodbye"],
    correct: "Good evening"
  },
  {
    question: "Which phrase correctly asks 'What is your name?'",
    options: ["Wie heißt du?", "Wie geht es dir?", "Wie alt bist du?"],
    correct: "Wie heißt du?"
  },
  {
    question: "How would you say 'See you soon'?",
    options: ["Bis bald", "Auf Wiedersehen", "Tschüss"],
    correct: "Bis bald"
  },
  {
    question: "What does 'Freut mich' convey?",
    options: ["Nice to meet you", "Thank you", "Sorry"],
    correct: "Nice to meet you"
  }
];

// Endpoint for "Sich vorstellen" quiz questions: return 5 random questions from 25 unique ones.
app.get('/api/quiz-questions/sich-vorstellen', (req, res) => {
  const randomQuestions = getRandomSubset(sichVorstellenUniqueQuestions, 5);
  res.json(randomQuestions);
});

/* *********************** 
   For "Im Café bestellen"
*********************** */
const cafeBestellenUniqueQuestions = [
  {
    question: "What is the German word for 'Coffee'?",
    options: ["Kaffee", "Tee", "Wasser"],
    correct: "Kaffee"
  },
  {
    question: "How do you say 'Cake' in German?",
    options: ["Kuchen", "Brot", "Milch"],
    correct: "Kuchen"
  },
  {
    question: "What does 'Bitte' typically mean when ordering?",
    options: ["Thank you", "Please", "Excuse me"],
    correct: "Please"
  },
  {
    question: "How do you ask for the menu?",
    options: ["Die Speisekarte, bitte", "Das Menü, bitte", "Die Rechnung, bitte"],
    correct: "Die Speisekarte, bitte"
  },
  {
    question: "Which phrase means 'I would like'?",
    options: ["Ich hätte gern", "Ich möchte", "Ich will"],
    correct: "Ich hätte gern"
  },
  {
    question: "What does 'Zucker' mean?",
    options: ["Milk", "Sugar", "Salt"],
    correct: "Sugar"
  },
  {
    question: "Which drink does 'Wasser' refer to?",
    options: ["Water", "Juice", "Soda"],
    correct: "Water"
  },
  {
    question: "How do you say 'The bill, please'?",
    options: ["Die Rechnung, bitte", "Die Speisekarte, bitte", "Das Menü, bitte"],
    correct: "Die Rechnung, bitte"
  },
  {
    question: "What is the common German word for 'Thank you'?",
    options: ["Danke", "Bitte", "Entschuldigung"],
    correct: "Danke"
  },
  {
    question: "How do you greet a server in a café?",
    options: ["Guten Tag", "Hallo", "Servus"],
    correct: "Guten Tag"
  },
  {
    question: "Which phrase implies a polite request?",
    options: ["Ich hätte gern", "Ich will", "Ich mag"],
    correct: "Ich hätte gern"
  },
  {
    question: "How do you request water politely?",
    options: ["Wasser, bitte", "Kaffee, bitte", "Rechnung, bitte"],
    correct: "Wasser, bitte"
  },
  {
    question: "What does 'Tee' mean in German?",
    options: ["Tea", "Coffee", "Juice"],
    correct: "Tea"
  },
  {
    question: "Which word represents 'menu' in German?",
    options: ["Speisekarte", "Menü", "Rechnung"],
    correct: "Speisekarte"
  },
  {
    question: "How would you say 'Goodbye' in a formal way in a café?",
    options: ["Auf Wiedersehen", "Tschüss", "Hallo"],
    correct: "Auf Wiedersehen"
  },
  {
    question: "What does 'Entschuldigung' mean?",
    options: ["Excuse me", "Thank you", "Goodbye"],
    correct: "Excuse me"
  },
  {
    question: "Which phrase is a polite greeting for a server?",
    options: ["Guten Tag", "Hi", "Tschüss"],
    correct: "Guten Tag"
  },
  {
    question: "How do you express gratitude for service?",
    options: ["Danke", "Bitte", "Entschuldigung"],
    correct: "Danke"
  },
  {
    question: "What is the informal farewell phrase?",
    options: ["Tschüss", "Auf Wiedersehen", "Servus"],
    correct: "Tschüss"
  },
  {
    question: "How do you say 'I am thirsty' in German?",
    options: ["Ich habe Durst", "Ich bin hungrig", "Ich bin müde"],
    correct: "Ich habe Durst"
  },
  {
    question: "Which phrase could be used to ask for recommendations?",
    options: ["Was empfehlen Sie?", "Wie spät ist es?", "Wo ist die Toilette?"],
    correct: "Was empfehlen Sie?"
  },
  {
    question: "What does 'Gerne' mean when responding to an order?",
    options: ["With pleasure", "No", "Maybe"],
    correct: "With pleasure"
  },
  {
    question: "How do you say 'Could I have...' in a polite form?",
    options: ["Könnte ich bitte...", "Ich will...", "Ich mag..."],
    correct: "Könnte ich bitte..."
  },
  {
    question: "Which expression implies a polite request for the bill?",
    options: ["Die Rechnung, bitte", "Das Menü, bitte", "Die Speisekarte, bitte"],
    correct: "Die Rechnung, bitte"
  }
];
app.get('/api/quiz-questions/im-cafe-bestellen', (req, res) => {
  const randomQuestions = getRandomSubset(cafeBestellenUniqueQuestions, 5);
  res.json(randomQuestions);
});

/* *********************** 
   For "Wegbeschreibungen"
*********************** */
const wegbeschreibungenUniqueQuestions = [
  {
    question: "What does 'geradeaus' mean?",
    options: ["Straight ahead", "Left", "Right"],
    correct: "Straight ahead"
  },
  {
    question: "How do you say 'left' in German?",
    options: ["links", "rechts", "geradeaus"],
    correct: "links"
  },
  {
    question: "What is the German word for 'intersection'?",
    options: ["Kreuzung", "Straße", "Bahnhof"],
    correct: "Kreuzung"
  },
  {
    question: "How do you say 'right' in German?",
    options: ["rechts", "links", "geradeaus"],
    correct: "rechts"
  },
  {
    question: "What does 'Wo ist der Bahnhof?' mean?",
    options: ["Where is the station?", "How far is the station?", "What time is the train?"],
    correct: "Where is the station?"
  },
  {
    question: "How do you say 'Turn left' in German?",
    options: ["Bitte links abbiegen", "Bitte rechts abbiegen", "Bitte geradeaus fahren"],
    correct: "Bitte links abbiegen"
  },
  {
    question: "What does 'Rechts abbiegen' mean?",
    options: ["Turn right", "Turn left", "Go straight"],
    correct: "Turn right"
  },
  {
    question: "Which phrase means 'Go straight'?",
    options: ["Geradeaus fahren", "Links fahren", "Rechts fahren"],
    correct: "Geradeaus fahren"
  },
  {
    question: "What is the German phrase for 'Where is the train station?'",
    options: ["Wo ist der Bahnhof?", "Wie komme ich zum Bahnhof?", "Wo ist die Kreuzung?"],
    correct: "Wo ist der Bahnhof?"
  },
  {
    question: "How do you formally ask for directions?",
    options: ["Entschuldigen Sie, wie komme ich zu...?", "Wie komme ich zu...?", "Wo ist...?"],
    correct: "Entschuldigen Sie, wie komme ich zu...?"
  },
  {
    question: "Which phrase would you use to say 'Turn left at the intersection'?",
    options: ["Bitte links abbiegen an der Kreuzung", "Bitte rechts abbiegen an der Kreuzung", "Bitte geradeaus fahren"],
    correct: "Bitte links abbiegen an der Kreuzung"
  },
  {
    question: "What does 'Am Bahnhof' mean?",
    options: ["At the station", "On the platform", "In the city"],
    correct: "At the station"
  },
  {
    question: "How do you say 'I need directions' in German?",
    options: ["Ich brauche eine Wegbeschreibung", "Ich brauche einen Kaffee", "Ich habe Hunger"],
    correct: "Ich brauche eine Wegbeschreibung"
  },
  {
    question: "What is the German term for 'crossing'?",
    options: ["Überquerung", "Kreuzung", "Brücke"],
    correct: "Kreuzung"
  },
  {
    question: "How would you say 'Go past the intersection'?",
    options: ["Gehen Sie an der Kreuzung vorbei", "Biegen Sie an der Kreuzung ab", "Fahren Sie an der Kreuzung entlang"],
    correct: "Gehen Sie an der Kreuzung vorbei"
  },
  {
    question: "Which question asks 'How do I get to...?'",
    options: ["Wie komme ich zu...?", "Wo ist...?", "Was ist...?"],
    correct: "Wie komme ich zu...?"
  },
  {
    question: "How would you instruct someone to 'Turn right at the next intersection'?",
    options: ["Biegen Sie an der nächsten Kreuzung rechts ab", "Biegen Sie an der nächsten Kreuzung links ab", "Gehen Sie geradeaus"],
    correct: "Biegen Sie an der nächsten Kreuzung rechts ab"
  },
  {
    question: "What is 'Kreuzung' in English?",
    options: ["Intersection", "Street", "Building"],
    correct: "Intersection"
  },
  {
    question: "How do you say 'Please, excuse me' formally?",
    options: ["Entschuldigen Sie bitte", "Bitte, danke", "Guten Tag"],
    correct: "Entschuldigen Sie bitte"
  },
  {
    question: "Which phrase means 'Follow the street'?",
    options: ["Folgen Sie der Straße", "Biegen Sie ab", "Gehen Sie geradeaus"],
    correct: "Folgen Sie der Straße"
  },
  {
    question: "How do you instruct 'Go straight for two blocks' in German?",
    options: ["Fahren Sie zwei Blocks geradeaus", "Biegen Sie ab", "Gehen Sie links"],
    correct: "Fahren Sie zwei Blocks geradeaus"
  },
  {
    question: "Which phrase would be used for 'Take the next left'?",
    options: ["Nehmen Sie die nächste linke Abzweigung", "Nehmen Sie die nächste rechte Abzweigung", "Gehen Sie geradeaus"],
    correct: "Nehmen Sie die nächste linke Abzweigung"
  },
  {
    question: "What does 'Links' mean in English?",
    options: ["Left", "Right", "Straight"],
    correct: "Left"
  },
  {
    question: "Which of these is a polite way to ask for directions?",
    options: ["Können Sie mir bitte sagen, wie ich zu...komme?", "Wo ist...?", "Was ist...?"],
    correct: "Können Sie mir bitte sagen, wie ich zu...komme?"
  },
  {
    question: "How do you express urgency when asking for directions?",
    options: ["Ich muss dringend wissen, wie ich zu...komme", "Ich möchte einen Kaffee", "Ich habe Hunger"],
    correct: "Ich muss dringend wissen, wie ich zu...komme"
  }
];
app.get('/api/quiz-questions/wegbeschreibungen', (req, res) => {
  const randomQuestions = getRandomSubset(wegbeschreibungenUniqueQuestions, 5);
  res.json(randomQuestions);
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
