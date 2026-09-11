// Spotify Playlist Generator
// OAuth 2.0 mit PKCE

const CLIENT_ID = "b7a1cad39a6e4ec6b3a82511b6b5e682";

const REDIRECT_URI =
    "https://christian-k80.github.io/spotify-playlist-generator/";

const SCOPES = [
    "playlist-modify-public",
    "playlist-modify-private"
];


// --------------------------------------------------
// Hilfsfunktionen für PKCE
// --------------------------------------------------

function generateRandomString(length) {
    const characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    let result = "";

    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);

    for (let i = 0; i < length; i++) {
        result += characters[randomValues[i] % characters.length];
    }

    return result;
}


async function generateCodeChallenge(codeVerifier) {

    const data = new TextEncoder().encode(codeVerifier);

    const digest = await crypto.subtle.digest(
        "SHA-256",
        data
    );

    return btoa(
        String.fromCharCode(...new Uint8Array(digest))
    )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}


// --------------------------------------------------
// Spotify Login
// --------------------------------------------------

async function loginWithSpotify() {

    const codeVerifier = generateRandomString(64);

    const codeChallenge =
        await generateCodeChallenge(codeVerifier);

    sessionStorage.setItem(
        "spotify_code_verifier",
        codeVerifier
    );

    const authorizationUrl =
        new URL("https://accounts.spotify.com/authorize");

    authorizationUrl.searchParams.set(
        "client_id",
        CLIENT_ID
    );

    authorizationUrl.searchParams.set(
        "response_type",
        "code"
    );

    authorizationUrl.searchParams.set(
        "redirect_uri",
        REDIRECT_URI
    );

    authorizationUrl.searchParams.set(
        "scope",
        SCOPES.join(" ")
    );

    authorizationUrl.searchParams.set(
        "code_challenge_method",
        "S256"
    );

    authorizationUrl.searchParams.set(
        "code_challenge",
        codeChallenge
    );

    window.location.href =
        authorizationUrl.toString();
}


// --------------------------------------------------
// Spotify Authorization Code gegen Access Token tauschen
// --------------------------------------------------

async function exchangeCodeForToken(code) {

    const codeVerifier =
        sessionStorage.getItem(
            "spotify_code_verifier"
        );

    if (!codeVerifier) {
        throw new Error(
            "PKCE-Code-Verifier wurde nicht gefunden."
        );
    }

    const body =
        new URLSearchParams();

    body.append(
        "client_id",
        CLIENT_ID
    );

    body.append(
        "grant_type",
        "authorization_code"
    );

    body.append(
        "code",
        code
    );

    body.append(
        "redirect_uri",
        REDIRECT_URI
    );

    body.append(
        "code_verifier",
        codeVerifier
    );


    const response =
        await fetch(
            "https://accounts.spotify.com/api/token",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },

                body: body.toString()
            }
        );


    if (!response.ok) {

        throw new Error(
            "Spotify Login konnte nicht abgeschlossen werden."
        );
    }


    const data =
        await response.json();


    sessionStorage.setItem(
        "spotify_access_token",
        data.access_token
    );

    sessionStorage.removeItem(
        "spotify_code_verifier"
    );

    return data;
}


// --------------------------------------------------
// URL auf Authorization Code prüfen
// --------------------------------------------------

async function handleAuthorizationCallback() {

    const url =
        new URL(window.location.href);

    const code =
        url.searchParams.get("code");

    const error =
        url.searchParams.get("error");


    if (error) {

        document.getElementById("login-status").textContent =
            "Spotify-Anmeldung wurde abgebrochen.";

        return;
    }


    if (!code) {
        return;
    }


    try {

        document.getElementById("login-status").textContent =
            "Spotify-Anmeldung wird abgeschlossen...";


        await exchangeCodeForToken(code);


        // Authorization Code aus der URL entfernen
        window.history.replaceState(
            {},
            document.title,
            REDIRECT_URI
        );


        updateLoginStatus();

    } catch (error) {

        console.error(error);

        document.getElementById("login-status").textContent =
            "Fehler bei der Spotify-Anmeldung.";
    }
}


// --------------------------------------------------
// Login-Status anzeigen
// --------------------------------------------------

function updateLoginStatus() {

    const token =
        sessionStorage.getItem(
            "spotify_access_token"
        );

    const status =
        document.getElementById(
            "login-status"
        );

    const button =
        document.getElementById(
            "login-button"
        );


    if (token) {

        status.textContent =
            "Mit Spotify verbunden.";

        button.textContent =
            "Mit Spotify verbunden";

        button.disabled = true;

    } else {

        status.textContent =
            "Noch nicht mit Spotify verbunden.";

        button.textContent =
            "Mit Spotify verbinden";

        button.disabled = false;
    }
}


// --------------------------------------------------
// Titel prüfen – zunächst nur Eingabe erkennen
// --------------------------------------------------

function validateTracks() {

    const input =
        document.getElementById(
            "track-input"
        ).value;


    const lines =
        input
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line !== "");


    const result =
        document.getElementById(
            "validation-result"
        );


    if (lines.length === 0) {

        result.textContent =
            "Keine Titel eingegeben.";

        return;
    }


    result.textContent =
        `${lines.length} Titel erkannt.`;
}


// --------------------------------------------------
// Event-Listener
// --------------------------------------------------

document
    .getElementById("login-button")
    .addEventListener(
        "click",
        loginWithSpotify
    );


document
    .getElementById("validate-button")
    .addEventListener(
        "click",
        validateTracks
    );


// --------------------------------------------------
// Anwendung starten
// --------------------------------------------------

handleAuthorizationCallback();

updateLoginStatus();
