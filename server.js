const express = require('express');
const cors = require('cors');
const session = require('express-session');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const app = express();
const PORT = process.env.PORT || 3000;

const CONFIG = {
    DISCORD_CLIENT_ID:     process.env.DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET: process.env.DISCORD_CLIENT_SECRET,
    DISCORD_REDIRECT_URI:  process.env.DISCORD_REDIRECT_URI,
    BOT_WEBHOOK_URL:       process.env.BOT_WEBHOOK_URL,
    BOT_SECRET:            process.env.BOT_SECRET || 'baconprotect-secret-2024',
    GUILD_ID:              process.env.GUILD_ID,
    SESSION_SECRET:        process.env.SESSION_SECRET || 'bacon-session-secret',
    FRONTEND_URL:          process.env.FRONTEND_URL || 'https://bacon-verifyrblx.netlify.app',
};

// CORS
const allowedOrigins = [
    'https://bacon-verifyrblx.netlify.app',
    'http://localhost:3000',
    'http://localhost:5500',
];

app.use(cors({
    origin: function(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json());

app.use(session({
    secret: CONFIG.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        sameSite: 'none',
        maxAge: 1000 * 60 * 60
    }
}));

// Health check
app.get('/', (req, res) => {
    res.json({ status: 'BaconProtect Backend Online 🥓' });
});

// Discord OAuth Step 1
app.get('/auth/discord', (req, res) => {
    const params = new URLSearchParams({
        client_id: CONFIG.DISCORD_CLIENT_ID,
        redirect_uri: CONFIG.DISCORD_REDIRECT_URI,
        response_type: 'code',
        scope: 'identify'
    });
    res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

// Discord OAuth Step 2
app.get('/auth/discord/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) return res.redirect(CONFIG.FRONTEND_URL + '?error=no_code');

    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id:     CONFIG.DISCORD_CLIENT_ID,
                client_secret: CONFIG.DISCORD_CLIENT_SECRET,
                grant_type:    'authorization_code',
                code:          code,
                redirect_uri:  CONFIG.DISCORD_REDIRECT_URI
            })
        });

        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) throw new Error('No access token from Discord');

        const userRes = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const user = await userRes.json();

        const snowflake = BigInt(user.id);
        const createdAt = new Date(Number((snowflake >> 22n) + 1420070400000n));
        const ageDays = Math.floor((Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24));

        req.session.discordUser = {
            id:        user.id,
            username:  user.username,
            avatarUrl: user.avatar
                ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
                : `https://cdn.discordapp.com/embed/avatars/0.png`,
            ageDays
        };

        res.redirect(CONFIG.FRONTEND_URL + '?discord=connected');

    } catch (e) {
        console.error('[Discord OAuth Error]', e);
        res.redirect(CONFIG.FRONTEND_URL + '?error=discord_failed');
    }
});

// Get Discord session
app.get('/auth/me', (req, res) => {
    if (req.session.discordUser) {
        res.json({ discord: req.session.discordUser });
    } else {
        res.json({ discord: null });
    }
});

// Logout
app.post('/auth/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Scan only
app.post('/scan/roblox', async (req, res) => {
    const { robloxId } = req.body;
    if (!robloxId || !/^\d+$/.test(robloxId)) {
        return res.status(400).json({ error: 'Invalid Roblox ID' });
    }
    try {
        const data = await fetchRobloxData(robloxId);
        res.json({ data, roleAssigned: false });
    } catch (e) {
        console.error('[Scan Error]', e);
        res.status(500).json({ error: e.message || 'Failed to fetch Roblox data' });
    }
});

// Verify with Discord
app.post('/verify/roblox', async (req, res) => {
    const { robloxId } = req.body;

    if (!robloxId || !/^\d+$/.test(robloxId)) {
        return res.status(400).json({ error: 'Invalid Roblox ID' });
    }

    if (!req.session.discordUser) {
        return res.status(401).json({ error: 'Not logged in with Discord' });
    }

    try {
        const data = await fetchRobloxData(robloxId);

        if (data.user && data.user.isBanned) {
            return res.status(403).json({ error: 'Banned Roblox account cannot be verified' });
        }

        let roleAssigned = false;
        if (CONFIG.BOT_WEBHOOK_URL && CONFIG.GUILD_ID) {
            try {
                const botRes = await fetch(CONFIG.BOT_WEBHOOK_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        discordId: req.session.discordUser.id,
                        guildId:   CONFIG.GUILD_ID,
                        secret:    CONFIG.BOT_SECRET
                    })
                });
                const botData = await botRes.json();
                roleAssigned = botData.success === true;
            } catch (e) {
                console.error('[Bot Webhook Error]', e.message);
            }
        }

        res.json({ data, roleAssigned });

    } catch (e) {
        console.error('[Verify Error]', e);
        res.status(500).json({ error: e.message || 'Verification failed' });
    }
});

// Roblox data fetcher
async function fetchRobloxData(robloxId) {
    const [userRes, badgesRes, groupsRes, inventoryRes] = await Promise.allSettled([
        fetch(`https://users.roblox.com/v1/users/${robloxId}`),
        fetch(`https://badges.roblox.com/v1/users/${robloxId}/badges?limit=25&sortOrder=Desc`),
        fetch(`https://groups.roblox.com/v2/users/${robloxId}/groups/roles?limit=25`),
        fetch(`https://inventory.roblox.com/v2/users/${robloxId}/inventory?assetTypes=Hat&limit=25`)
    ]);

    if (userRes.status === 'rejected') throw new Error('Could not reach Roblox API');

    const userJson = await userRes.value.json();
    if (userJson.errors) throw new Error('Roblox user not found');

    const badges    = badgesRes.status    === 'fulfilled' ? (await badgesRes.value.json()).data    || [] : [];
    const groups    = groupsRes.status    === 'fulfilled' ? (await groupsRes.value.json()).data    || [] : [];
    const inventory = inventoryRes.status === 'fulfilled' ? (await inventoryRes.value.json()).data || [] : [];

    let avatarUrl = null;
    try {
        const avatarRes = await fetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${robloxId}&size=150x150&format=Png`);
        const avatarJson = await avatarRes.json();
        avatarUrl = avatarJson.data?.[0]?.imageUrl || null;
    } catch (e) {}

    return {
        user: {
            id:          userJson.id,
            name:        userJson.name,
            displayName: userJson.displayName,
            description: userJson.description,
            isBanned:    userJson.isBanned
        },
        badges,
        groups,
        inventory,
        avatarUrl
    };
}

app.listen(PORT, () => {
    console.log(`🥓 BaconProtect Backend running on port ${PORT}`);
});
