// Spotify Playlist Generator
// OAuth 2.0 mit PKCE

const CLIENT_ID = "b7a1cad39a6e4ec6b3a82511b6b5e682";

const REDIRECT_URI =
    "https://christian-k80.github.io/spotify-playlist-generator/";

const SCOPES = [
    "playlist-modify-public",
    "playlist-modify-private"
];

// Anzahl gleichzeitiger Einzel-Requests bei der Titelprüfung.
// Höher = schneller, aber größeres Risiko für 429 (Rate Limit).
const VALIDATE_CONCURRENCY = 5;

// Spotify erlaubt maximal 100 Titel pro Anfrage beim Hinzufügen
// zu einer Playlist.
const ADD_TRACKS_BATCH_SIZE = 100;


// --------------------------------------------------
// PKCE
// --------------------------------------------------

function generateRandomString(length) {

    const characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    let result = "";

    const randomValues = new Uint8Array(length);

    crypto.getRandomValues(randomValues);

    for (let i = 0; i < length; i++) {

        result +=
            characters[randomValues[i] % characters.length];
    }

    return result;
}


async function generateCodeChallenge(codeVerifier) {

    const data =
        new TextEncoder().encode(codeVerifier);

    const digest =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );

    return btoa(
        String.fromCharCode(
            ...new Uint8Array(digest)
        )
    )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}


// --------------------------------------------------
// Spotify Login
// --------------------------------------------------

async function loginWithSpotify() {

    const codeVerifier =
        generateRandomString(64);

    const codeChallenge =
        await generateCodeChallenge(
            codeVerifier
        );

    sessionStorage.setItem(
        "spotify_code_verifier",
        codeVerifier
    );

    const authorizationUrl =
        new URL(
            "https://accounts.spotify.com/authorize"
        );

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
// Code gegen Access Token tauschen
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
// Rückkehr von Spotify verarbeiten
// --------------------------------------------------

async function handleAuthorizationCallback() {

    const url =
        new URL(window.location.href);

    const code =
        url.searchParams.get("code");

    const error =
        url.searchParams.get("error");


    if (error) {

        document.getElementById(
            "login-status"
        ).textContent =
            "Spotify-Anmeldung wurde abgebrochen.";

        return;
    }


    if (!code) {
        return;
    }


    try {

        document.getElementById(
            "login-status"
        ).textContent =
            "Spotify-Anmeldung wird abgeschlossen...";


        await exchangeCodeForToken(code);


        window.history.replaceState(
            {},
            document.title,
            REDIRECT_URI
        );


        updateLoginStatus();

    } catch (error) {

        console.error(error);

        document.getElementById(
            "login-status"
        ).textContent =
            "Fehler bei der Spotify-Anmeldung.";
    }
}


// --------------------------------------------------
// Login-Status
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
// Spotify Track URI erkennen
// --------------------------------------------------

function extractTrackId(input) {

    const value =
        input.trim();


    // Spotify URI
    const uriMatch =
        value.match(
            /^spotify:track:([a-zA-Z0-9]+)$/
        );


    if (uriMatch) {

        return uriMatch[1];
    }


    // Spotify URL
    try {

        const url =
            new URL(value);

        if (
            url.hostname === "open.spotify.com"
        ) {

            const pathParts =
                url.pathname.split("/");

            const trackIndex =
                pathParts.indexOf("track");

            if (
                trackIndex !== -1 &&
                pathParts[trackIndex + 1]
            ) {

                return pathParts[
                    trackIndex + 1
                ];
            }
        }

    } catch {
        // Keine gültige URL
    }


    // Direkte Track-ID
    if (
        /^[a-zA-Z0-9]{22}$/.test(value)
    ) {

        return value;
    }


    return null;
}


// --------------------------------------------------
// Hilfsfunktionen: Nebenläufigkeit & Rate Limits
// --------------------------------------------------

// Führt "worker" für jedes Element in "items" aus, aber maximal
// "limit" Aufrufe gleichzeitig. "onProgress" wird nach jedem
// abgeschlossenen Element aufgerufen.
async function runWithConcurrencyLimit(items, limit, worker, onProgress) {

    const results =
        new Array(items.length);

    let nextIndex = 0;
    let completed = 0;

    async function runNext() {

        while (nextIndex < items.length) {

            const currentIndex =
                nextIndex;

            nextIndex += 1;

            results[currentIndex] =
                await worker(
                    items[currentIndex],
                    currentIndex
                );

            completed += 1;

            if (onProgress) {

                onProgress(
                    completed,
                    items.length
                );
            }
        }
    }

    const workerCount =
        Math.min(limit, items.length);

    const runners = [];

    for (let i = 0; i < workerCount; i++) {

        runners.push(runNext());
    }

    await Promise.all(runners);

    return results;
}


// Führt einen fetch-Aufruf aus und wartet bei einer 429-Antwort
// (Rate Limit) automatisch die von Spotify vorgegebene Zeit ab,
// bevor es erneut versucht wird.
async function fetchWithRateLimitRetry(url, options) {

    while (true) {

        const response =
            await fetch(url, options);

        if (response.status !== 429) {

            return response;
        }

        const retryAfterHeader =
            response.headers.get("Retry-After");

        const retryAfterSeconds =
            retryAfterHeader ?
                parseInt(retryAfterHeader, 10) :
                1;

        await new Promise(
            resolve => setTimeout(
                resolve,
                (retryAfterSeconds || 1) * 1000
            )
        );
    }
}


// --------------------------------------------------
// Spotify Tracks prüfen
// --------------------------------------------------

async function validateTracks() {

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


    const accessToken =
        sessionStorage.getItem(
            "spotify_access_token"
        );


    if (!accessToken) {

        result.textContent =
            "Bitte zuerst mit Spotify verbinden.";

        return;
    }


    const trackIds = [];
    const invalidEntries = [];


    for (const line of lines) {

        const trackId =
            extractTrackId(line);


        if (trackId) {

            trackIds.push(trackId);

        } else {

            invalidEntries.push(line);
        }
    }


    if (trackIds.length === 0) {

        result.textContent =
            "Keine gültigen Spotify-Track-IDs gefunden.";

        return;
    }


    result.textContent =
        `Titel werden geprüft... (0 / ${trackIds.length})`;


    let sessionExpired = false;


    try {

        const trackResults =
            await runWithConcurrencyLimit(
                trackIds,
                VALIDATE_CONCURRENCY,

                async (trackId) => {

                    if (sessionExpired) {

                        // Keine weiteren Anfragen mehr senden,
                        // sobald die Sitzung abgelaufen ist.
                        return null;
                    }

                    const response =
                        await fetchWithRateLimitRetry(
                            `https://api.spotify.com/v1/tracks/${trackId}`,
                            {
                                method: "GET",

                                headers: {
                                    Authorization:
                                        `Bearer ${accessToken}`
                                }
                            }
                        );


                    if (response.status === 401) {

                        sessionExpired = true;

                        return null;
                    }


                    if (response.status === 404) {

                        return { found: false };
                    }


                    if (!response.ok) {

                        throw new Error(
                            `Spotify API Fehler: ${response.status}`
                        );
                    }


                    await response.json();

                    return { found: true };
                },

                (completed, total) => {

                    result.textContent =
                        `Titel werden geprüft... (${completed} / ${total})`;
                }
            );


        if (sessionExpired) {

            sessionStorage.removeItem(
                "spotify_access_token"
            );

            updateLoginStatus();

            result.textContent =
                "Die Spotify-Sitzung ist abgelaufen. Bitte erneut anmelden.";

            return;
        }


        const validCount =
            trackResults.filter(
                track => track && track.found
            ).length;


        const notFoundCount =
            trackResults.filter(
                track => track && !track.found
            ).length;


        let message =
            `${validCount} gültige Titel gefunden.`;


        if (notFoundCount > 0) {

            message +=
                ` ${notFoundCount} Titel wurden nicht gefunden.`;
        }


        if (invalidEntries.length > 0) {

            message +=
                ` ${invalidEntries.length} Eingabe(n) sind keine gültige Spotify-Track-ID, URI oder URL.`;
        }


        result.textContent =
            message;


    } catch (error) {

        console.error(error);

        result.textContent =
            "Die Titel konnten nicht bei Spotify geprüft werden.";
    }
}

// --------------------------------------------------
// Spotify Playlist erstellen
// --------------------------------------------------

async function createPlaylist() {

    const accessToken =
        sessionStorage.getItem(
            "spotify_access_token"
        );

    const playlistName =
        document.getElementById(
            "playlist-name"
        ).value.trim();

    const input =
        document.getElementById(
            "track-input"
        ).value;


    const result =
        document.getElementById(
            "playlist-result"
        );


    if (!accessToken) {

        result.textContent =
            "Bitte zuerst mit Spotify verbinden.";

        return;
    }


    if (!playlistName) {

        result.textContent =
            "Bitte einen Playlist-Namen eingeben.";

        return;
    }


    const lines =
        input
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line !== "");


    if (lines.length === 0) {

        result.textContent =
            "Bitte mindestens einen Titel eingeben.";

        return;
    }


    const trackIds = [];

    for (const line of lines) {

        const trackId =
            extractTrackId(line);

        if (trackId) {
            trackIds.push(trackId);
        }
    }


    if (trackIds.length === 0) {

        result.textContent =
            "Es wurden keine gültigen Spotify-Titel gefunden.";

        return;
    }


    result.textContent =
        `Playlist wird erstellt... (0 / ${trackIds.length} Titel hinzugefügt)`;


    try {

        // ------------------------------------------
        // 1. Playlist erstellen
        // ------------------------------------------

        const playlistResponse =
            await fetchWithRateLimitRetry(
                "https://api.spotify.com/v1/me/playlists",
                {
                    method: "POST",

                    headers: {
                        Authorization:
                            `Bearer ${accessToken}`,

                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        name: playlistName,
                        public: false,
                        collaborative: false,
                        description:
                            "Erstellt mit dem Spotify Playlist Generator"
                    })
                }
            );


        if (!playlistResponse.ok) {

            throw new Error(
                `Playlist konnte nicht erstellt werden (${playlistResponse.status}).`
            );
        }


        const playlist =
            await playlistResponse.json();


        // ------------------------------------------
        // 2. Titel zur Playlist hinzufügen
        // ------------------------------------------

        const trackUris =
            trackIds.map(
                id => `spotify:track:${id}`
            );


        let addedCount = 0;


        // Spotify erlaubt maximal 100 Titel pro Anfrage. Bei sehr
        // vielen Titeln werden die Batches nacheinander (nicht
        // parallel) verschickt, damit kein Rate Limit ausgelöst wird.

        for (
            let i = 0;
            i < trackUris.length;
            i += ADD_TRACKS_BATCH_SIZE
        ) {

            const batch =
                trackUris.slice(
                    i,
                    i + ADD_TRACKS_BATCH_SIZE
                );


            const tracksResponse =
                await fetchWithRateLimitRetry(
                    `https://api.spotify.com/v1/playlists/${playlist.id}/items`,
                    {
                        method: "POST",

                        headers: {
                            Authorization:
                                `Bearer ${accessToken}`,

                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            uris: batch
                        })
                    }
                );


            if (!tracksResponse.ok) {

                throw new Error(
                    `Titel konnten nicht hinzugefügt werden (${tracksResponse.status}).`
                );
            }


            addedCount += batch.length;

            result.textContent =
                `Playlist wird erstellt... (${addedCount} / ${trackUris.length} Titel hinzugefügt)`;
        }


        // ------------------------------------------
        // 3. Ergebnis anzeigen
        // ------------------------------------------

        result.innerHTML = `
            <p>
                <strong>Playlist erfolgreich erstellt.</strong>
            </p>

            <p>
                ${trackIds.length} Titel wurden hinzugefügt.
            </p>

            <p>
                <a
                    href="${playlist.external_urls.spotify}"
                    target="_blank"
                    rel="noopener"
                >
                    Playlist in Spotify öffnen
                </a>
            </p>
        `;


    } catch (error) {

        console.error(error);

        result.textContent =
            error.message ||
            "Die Playlist konnte nicht erstellt werden.";
    }
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

document
    .getElementById("create-playlist-button")
    .addEventListener(
        "click",
        createPlaylist
    );

// --------------------------------------------------
// Anwendung starten
// --------------------------------------------------

handleAuthorizationCallback();

updateLoginStatus();
