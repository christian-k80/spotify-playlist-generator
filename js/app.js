// Spotify Playlist Generator
// OAuth 2.0 mit PKCE + Refresh-Token + CSRF-Schutz (state)
// + Playlist-Erstellung aus TXT-Dateien per Drag & Drop

const CLIENT_ID = "b7a1cad39a6e4ec6b3a82511b6b5e682";

const REDIRECT_URI =
    "https://christian-k80.github.io/spotify-playlist-generator/";

const SCOPES = [
    "playlist-modify-public",
    "playlist-modify-private"
];

// Maximale Anzahl an Wiederholungsversuchen bei 429 (Rate Limit),
// bevor abgebrochen wird.
const MAX_RATE_LIMIT_RETRIES = 8;

// Spotify erlaubt maximal 100 Titel pro Anfrage beim Hinzufügen
// zu einer Playlist.
const ADD_TRACKS_BATCH_SIZE = 100;

// Nach dieser Zeit ohne Antwort wird eine einzelne Anfrage abgebrochen.
const FETCH_TIMEOUT_MS = 15000;

// Der Access Token wird schon dieses viele Sekunden VOR dem
// eigentlichen Ablauf erneuert, damit ein Request nicht mitten in
// der Ausführung mit 401 fehlschlägt.
const TOKEN_REFRESH_MARGIN_SECONDS = 60;

// Spotify-übliche Obergrenze für Playlist-Namen in der UI.
const MAX_PLAYLIST_NAME_LENGTH = 100;


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
        result += characters[randomValues[i] % characters.length];
    }

    return result;
}


async function generateCodeChallenge(codeVerifier) {

    const data = new TextEncoder().encode(codeVerifier);
    const digest = await crypto.subtle.digest("SHA-256", data);

    return btoa(String.fromCharCode(...new Uint8Array(digest)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}


// --------------------------------------------------
// Token-Speicherung
// --------------------------------------------------

function storeTokenData(data) {

    sessionStorage.setItem("spotify_access_token", data.access_token);

    if (data.refresh_token) {
        sessionStorage.setItem("spotify_refresh_token", data.refresh_token);
    }

    if (data.expires_in) {
        const expiresAt = Date.now() + data.expires_in * 1000;
        sessionStorage.setItem("spotify_token_expires_at", String(expiresAt));
    }
}


function getStoredAccessToken() {
    return sessionStorage.getItem("spotify_access_token");
}


function getStoredRefreshToken() {
    return sessionStorage.getItem("spotify_refresh_token");
}


function isAccessTokenExpired() {

    const expiresAt = sessionStorage.getItem("spotify_token_expires_at");

    if (!expiresAt) {
        return true;
    }

    return Date.now() > (Number(expiresAt) - TOKEN_REFRESH_MARGIN_SECONDS * 1000);
}


function clearAllAuthData() {

    sessionStorage.removeItem("spotify_access_token");
    sessionStorage.removeItem("spotify_refresh_token");
    sessionStorage.removeItem("spotify_token_expires_at");
    sessionStorage.removeItem("spotify_code_verifier");
    sessionStorage.removeItem("spotify_oauth_state");
}


// --------------------------------------------------
// Spotify Login
// --------------------------------------------------

async function loginWithSpotify() {

    const codeVerifier = generateRandomString(64);
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const state = generateRandomString(16);

    sessionStorage.setItem("spotify_code_verifier", codeVerifier);
    sessionStorage.setItem("spotify_oauth_state", state);

    const authorizationUrl = new URL("https://accounts.spotify.com/authorize");

    authorizationUrl.searchParams.set("client_id", CLIENT_ID);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("redirect_uri", REDIRECT_URI);
    authorizationUrl.searchParams.set("scope", SCOPES.join(" "));
    authorizationUrl.searchParams.set("state", state);
    authorizationUrl.searchParams.set("code_challenge_method", "S256");
    authorizationUrl.searchParams.set("code_challenge", codeChallenge);

    window.location.href = authorizationUrl.toString();
}


// --------------------------------------------------
// Code gegen Access Token tauschen
// --------------------------------------------------

async function exchangeCodeForToken(code) {

    const codeVerifier = sessionStorage.getItem("spotify_code_verifier");

    if (!codeVerifier) {
        throw new Error("PKCE-Code-Verifier wurde nicht gefunden.");
    }

    const body = new URLSearchParams();

    body.append("client_id", CLIENT_ID);
    body.append("grant_type", "authorization_code");
    body.append("code", code);
    body.append("redirect_uri", REDIRECT_URI);
    body.append("code_verifier", codeVerifier);

    const response = await fetch("https://accounts.spotify.com/api/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString()
    });

    if (!response.ok) {
        throw new Error("Spotify Login konnte nicht abgeschlossen werden.");
    }

    const data = await response.json();

    storeTokenData(data);
    sessionStorage.removeItem("spotify_code_verifier");

    return data;
}


// --------------------------------------------------
// Access Token per Refresh Token erneuern
// --------------------------------------------------

async function refreshAccessToken() {

    const refreshToken = getStoredRefreshToken();

    if (!refreshToken) {
        return null;
    }

    const body = new URLSearchParams();

    body.append("client_id", CLIENT_ID);
    body.append("grant_type", "refresh_token");
    body.append("refresh_token", refreshToken);

    try {

        const response = await fetch("https://accounts.spotify.com/api/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString()
        });

        if (!response.ok) {
            return null;
        }

        const data = await response.json();

        storeTokenData(data);

        return data.access_token;

    } catch (error) {

        console.error("Refresh fehlgeschlagen:", error);
        return null;
    }
}


async function getValidAccessToken() {

    const accessToken = getStoredAccessToken();

    if (!accessToken) {
        return null;
    }

    if (!isAccessTokenExpired()) {
        return accessToken;
    }

    const refreshedToken = await refreshAccessToken();

    if (!refreshedToken) {
        clearAllAuthData();
        return null;
    }

    return refreshedToken;
}


// --------------------------------------------------
// Rückkehr von Spotify verarbeiten
// --------------------------------------------------

async function handleAuthorizationCallback() {

    const url = new URL(window.location.href);
    const code = url.searchParams.get("code");
    const error = url.searchParams.get("error");
    const returnedState = url.searchParams.get("state");

    if (error) {

        document.getElementById("login-status").textContent =
            "Spotify-Anmeldung wurde abgebrochen.";

        clearAllAuthData();
        window.history.replaceState({}, document.title, REDIRECT_URI);
        return;
    }

    if (!code) {
        return;
    }

    const expectedState = sessionStorage.getItem("spotify_oauth_state");

    if (!returnedState || returnedState !== expectedState) {

        document.getElementById("login-status").textContent =
            "Sicherheitsprüfung fehlgeschlagen (state stimmt nicht überein). Bitte erneut anmelden.";

        clearAllAuthData();
        window.history.replaceState({}, document.title, REDIRECT_URI);
        return;
    }

    sessionStorage.removeItem("spotify_oauth_state");

    try {

        document.getElementById("login-status").textContent =
            "Spotify-Anmeldung wird abgeschlossen...";

        await exchangeCodeForToken(code);

        window.history.replaceState({}, document.title, REDIRECT_URI);

        await updateLoginStatus();

    } catch (error) {

        console.error(error);

        document.getElementById("login-status").textContent =
            "Fehler bei der Spotify-Anmeldung.";

        clearAllAuthData();
    }
}


// --------------------------------------------------
// Login-Status
// --------------------------------------------------

async function updateLoginStatus() {

    const status = document.getElementById("login-status");
    const button = document.getElementById("login-button");

    const accessToken = await getValidAccessToken();

    if (accessToken) {

        status.textContent = "Mit Spotify verbunden.";
        button.textContent = "Mit Spotify verbunden";
        button.disabled = true;

    } else {

        status.textContent = "Noch nicht mit Spotify verbunden.";
        button.textContent = "Mit Spotify verbinden";
        button.disabled = false;
    }
}


// --------------------------------------------------
// Spotify Track URI erkennen
// --------------------------------------------------

function extractTrackId(input) {

    const value = input.trim();

    const uriMatch = value.match(/^spotify:track:([a-zA-Z0-9]+)$/);

    if (uriMatch) {
        return uriMatch[1];
    }

    try {

        const url = new URL(value);

        if (url.hostname === "open.spotify.com") {

            const pathParts = url.pathname.split("/");
            const trackIndex = pathParts.indexOf("track");

            if (trackIndex !== -1 && pathParts[trackIndex + 1]) {
                return pathParts[trackIndex + 1];
            }
        }

    } catch {
        // Keine gültige URL
    }

    if (/^[a-zA-Z0-9]{22}$/.test(value)) {
        return value;
    }

    return null;
}


// --------------------------------------------------
// Track-Zeilen parsen (für Textfeld UND für Dateien)
// --------------------------------------------------

// Zerlegt einen mehrzeiligen Text in gültige Track-IDs (dedupliziert)
// und ungültige Zeilen. Wird sowohl von der manuellen Texteingabe
// als auch beim Einlesen von TXT-Dateien verwendet.
function parseTrackLines(text) {

    const lines = text
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(line => line !== "");

    const rawTrackIds = [];
    const invalidEntries = [];

    for (const line of lines) {

        const trackId = extractTrackId(line);

        if (trackId) {
            rawTrackIds.push(trackId);
        } else {
            invalidEntries.push(line);
        }
    }

    const trackIds = [...new Set(rawTrackIds)];
    const duplicateCount = rawTrackIds.length - trackIds.length;

    return { trackIds, invalidEntries, duplicateCount };
}


// --------------------------------------------------
// Hilfsfunktion: Fetch mit Timeout
// --------------------------------------------------

async function fetchWithTimeout(url, options = {}) {

    const controller = new AbortController();

    const timeoutId = setTimeout(
        () => controller.abort(),
        FETCH_TIMEOUT_MS
    );

    try {

        return await fetch(url, { ...options, signal: controller.signal });

    } catch (error) {

        if (error.name === "AbortError") {
            throw new Error("Zeitüberschreitung: Spotify hat nicht rechtzeitig geantwortet.");
        }

        throw error;

    } finally {

        clearTimeout(timeoutId);
    }
}


// --------------------------------------------------
// Hilfsfunktion: Rate Limits
// --------------------------------------------------

async function fetchWithRateLimitRetry(url, options, onWaiting) {

    let attempt = 0;
    let backoffSeconds = 1;

    while (true) {

        const response = await fetchWithTimeout(url, options);

        if (response.status !== 429) {
            return response;
        }

        attempt += 1;

        if (attempt > MAX_RATE_LIMIT_RETRIES) {
            throw new Error("Spotify Rate Limit: zu viele Wiederholungsversuche.");
        }

        const retryAfterHeader = response.headers.get("Retry-After");

        const waitSeconds = retryAfterHeader ?
            (parseInt(retryAfterHeader, 10) || 1) :
            backoffSeconds;

        if (!retryAfterHeader) {
            backoffSeconds = Math.min(backoffSeconds * 2, 30);
        }

        if (onWaiting) {
            onWaiting(waitSeconds, attempt);
        }

        await new Promise(resolve => setTimeout(resolve, waitSeconds * 1000));
    }
}


// --------------------------------------------------
// Hilfsfunktion: Authentifizierte Spotify-API-Aufrufe
// --------------------------------------------------

async function fetchSpotifyApi(url, options, onWaiting) {

    const accessToken = await getValidAccessToken();

    if (!accessToken) {
        throw new Error("Nicht mit Spotify verbunden. Bitte erneut anmelden.");
    }

    const buildOptions = (token) => ({
        ...options,
        headers: {
            ...(options?.headers || {}),
            Authorization: `Bearer ${token}`
        }
    });

    let response = await fetchWithRateLimitRetry(
        url,
        buildOptions(accessToken),
        onWaiting
    );

    if (response.status === 401) {

        const refreshedToken = await refreshAccessToken();

        if (!refreshedToken) {
            clearAllAuthData();
            throw new Error("Sitzung abgelaufen. Bitte erneut mit Spotify verbinden.");
        }

        response = await fetchWithRateLimitRetry(
            url,
            buildOptions(refreshedToken),
            onWaiting
        );
    }

    return response;
}


async function buildApiErrorMessage(response, fallbackMessage) {

    try {

        const data = await response.json();
        const detail = data?.error?.message;

        if (detail) {
            return `${fallbackMessage} (${response.status}: ${detail})`;
        }

    } catch {
        // Body war kein JSON oder leer - Fallback verwenden.
    }

    return `${fallbackMessage} (${response.status})`;
}


// --------------------------------------------------
// Titel-Eingabe lokal prüfen (ohne Spotify-Anfrage)
// --------------------------------------------------

function validateTracks() {

    const input = document.getElementById("track-input").value;
    const result = document.getElementById("validation-result");

    if (input.trim() === "") {
        result.textContent = "Keine Titel eingegeben.";
        return;
    }

    const { trackIds, invalidEntries, duplicateCount } = parseTrackLines(input);

    let message = `${trackIds.length + duplicateCount} gültig formatierte Titel gefunden.`;

    if (duplicateCount > 0) {
        message += ` Davon sind ${duplicateCount} Duplikat(e).`;
    }

    if (invalidEntries.length > 0) {
        message += ` ${invalidEntries.length} Eingabe(n) sind keine gültige Spotify-Track-ID, URI oder URL.`;
    }

    message += " Ob die Titel bei Spotify tatsächlich existieren, wird beim Erstellen der Playlist geprüft.";

    result.textContent = message;
}


// --------------------------------------------------
// Kernfunktion: Eine Playlist aus Track-IDs erstellen
// --------------------------------------------------

// Erstellt eine Playlist mit dem angegebenen Namen und fügt die
// übergebenen Track-IDs hinzu. onStatus(text) wird für laufende
// Fortschritts-/Warteinformationen aufgerufen (z. B. Rate-Limit-
// Wartezeiten). Wird sowohl von der manuellen Eingabe als auch vom
// Datei-Batch verwendet, damit die Kernlogik nur an einer Stelle
// gepflegt werden muss.
async function createPlaylistFromTracks(playlistName, trackIds, onStatus) {

    const notify = (text) => {
        if (onStatus) onStatus(text);
    };

    // ------------------------------------------
    // 1. Playlist erstellen
    // ------------------------------------------

    notify(`Playlist "${playlistName}" wird erstellt... (0 / ${trackIds.length} Titel hinzugefügt)`);

    const playlistResponse = await fetchSpotifyApi(
        "https://api.spotify.com/v1/me/playlists",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: playlistName,
                public: false,
                collaborative: false,
                description: "Erstellt mit dem Spotify Playlist Generator"
            })
        },
        (waitSeconds) => notify(`Spotify bremst kurz (Rate Limit) – warte ${waitSeconds}s...`)
    );

    if (!playlistResponse.ok) {
        throw new Error(
            await buildApiErrorMessage(playlistResponse, "Playlist konnte nicht erstellt werden")
        );
    }

    const playlist = await playlistResponse.json();

    // ------------------------------------------
    // 2. Titel zur Playlist hinzufügen
    // ------------------------------------------

    const trackUris = trackIds.map(id => `spotify:track:${id}`);

    let addedCount = 0;

    for (let i = 0; i < trackUris.length; i += ADD_TRACKS_BATCH_SIZE) {

        const batch = trackUris.slice(i, i + ADD_TRACKS_BATCH_SIZE);

        const tracksResponse = await fetchSpotifyApi(
            `https://api.spotify.com/v1/playlists/${playlist.id}/items`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ uris: batch })
            },
            (waitSeconds) => notify(`Spotify bremst kurz (Rate Limit) – warte ${waitSeconds}s...`)
        );

        if (!tracksResponse.ok) {
            throw new Error(
                await buildApiErrorMessage(tracksResponse, "Titel konnten nicht hinzugefügt werden")
            );
        }

        addedCount += batch.length;

        notify(`Playlist "${playlistName}" wird erstellt... (${addedCount} / ${trackUris.length} Titel hinzugefügt)`);
    }

    // ------------------------------------------
    // 3. Tatsächliche Titelanzahl prüfen
    // ------------------------------------------

    let actualTrackCount = null;

    const playlistDetailsResponse = await fetchSpotifyApi(
        `https://api.spotify.com/v1/playlists/${playlist.id}`,
        { method: "GET" },
        (waitSeconds) => notify(`Spotify bremst kurz (Rate Limit) – warte ${waitSeconds}s...`)
    );

    if (playlistDetailsResponse.ok) {

        const playlistDetails = await playlistDetailsResponse.json();

        actualTrackCount =
            playlistDetails.items?.total ??
            playlistDetails.tracks?.total ??
            null;
    }

    return {
        playlist,
        requestedCount: trackIds.length,
        actualTrackCount
    };
}


// --------------------------------------------------
// Manuelle Playlist-Erstellung (Textfeld)
// --------------------------------------------------

async function createPlaylist() {

    const createButton = document.getElementById("create-playlist-button");

    if (createButton.disabled) {
        return;
    }

    const playlistName = document.getElementById("playlist-name").value.trim();
    const input = document.getElementById("track-input").value;
    const result = document.getElementById("playlist-result");

    if (!playlistName) {
        result.textContent = "Bitte einen Playlist-Namen eingeben.";
        return;
    }

    if (playlistName.length > MAX_PLAYLIST_NAME_LENGTH) {
        result.textContent =
            `Der Playlist-Name ist zu lang (max. ${MAX_PLAYLIST_NAME_LENGTH} Zeichen).`;
        return;
    }

    const { trackIds } = parseTrackLines(input);

    if (trackIds.length === 0) {
        result.textContent = "Es wurden keine gültigen Spotify-Titel gefunden.";
        return;
    }

    createButton.disabled = true;

    try {

        const { playlist, requestedCount, actualTrackCount } =
            await createPlaylistFromTracks(
                playlistName,
                trackIds,
                (text) => { result.textContent = text; }
            );

        result.innerHTML = buildPlaylistResultHtml(playlist, requestedCount, actualTrackCount);

    } catch (error) {

        console.error(error);

        result.textContent =
            error.message || "Die Playlist konnte nicht erstellt werden.";

        await updateLoginStatus();

    } finally {

        createButton.disabled = false;
    }
}


// Baut die ausführliche Erfolgs-/Abweichungs-Meldung inkl. Link
// zur Playlist (identisch zur bisherigen Darstellung).
function buildPlaylistResultHtml(playlist, requestedCount, actualTrackCount) {

    const countMatches = actualTrackCount === requestedCount;

    let statusHtml;

    if (actualTrackCount === null) {

        statusHtml = `
            <p>
                ${requestedCount} Titel wurden übermittelt. Die
                tatsächliche Anzahl in der Playlist konnte nicht
                abgerufen werden - bitte in Spotify kontrollieren.
            </p>
        `;

    } else if (countMatches) {

        statusHtml = `
            <p>
                Alle ${actualTrackCount} Titel wurden erfolgreich
                hinzugefügt.
            </p>
        `;

    } else {

        const missingCount = requestedCount - actualTrackCount;

        statusHtml = `
            <p>
                Die Playlist enthält ${actualTrackCount} von
                ${requestedCount} übermittelten Titeln.
                ${missingCount} Titel konnten nicht hinzugefügt
                werden (z. B. weil die Track-ID bei Spotify nicht
                existiert).
            </p>
        `;
    }

    return `
        <p>
            <strong>Playlist "${playlist.name}" erfolgreich erstellt.</strong>
        </p>

        ${statusHtml}

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
}


// --------------------------------------------------
// Playlist-Erstellung aus TXT-Dateien (Drag & Drop)
// --------------------------------------------------

// fileQueue enthält ein Objekt pro Datei, solange sie noch nicht
// (oder gerade) verarbeitet wurde:
// { id, fileName, playlistName, trackIds, invalidCount, status, resultHtml }
let fileQueue = [];

function generateQueueId() {
    return (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);
}


// Leitet aus einem Dateinamen den Playlist-Namen ab: Endung ".txt"
// entfernen, trimmen, auf die Spotify-übliche Maximallänge kürzen.
function derivePlaylistNameFromFileName(fileName) {

    const withoutExtension = fileName.replace(/\.txt$/i, "").trim();
    const fallbackName = withoutExtension || "Playlist";

    return fallbackName.length > MAX_PLAYLIST_NAME_LENGTH ?
        fallbackName.slice(0, MAX_PLAYLIST_NAME_LENGTH) :
        fallbackName;
}


async function addFilesToQueue(fileList) {

    const files = Array.from(fileList);

    const txtFiles = files.filter(
        file => file.name.toLowerCase().endsWith(".txt")
    );

    const skippedCount = files.length - txtFiles.length;

    for (const file of txtFiles) {

        let content = "";

        try {
            content = await file.text();
        } catch (error) {
            console.error(`Datei "${file.name}" konnte nicht gelesen werden:`, error);
            continue;
        }

        const { trackIds, invalidEntries } = parseTrackLines(content);

        fileQueue.push({
            id: generateQueueId(),
            fileName: file.name,
            playlistName: derivePlaylistNameFromFileName(file.name),
            trackIds,
            invalidCount: invalidEntries.length,
            status: "pending" // pending | creating | done | error
        });
    }

    renderFileQueue(skippedCount);
}


function removeFileFromQueue(id) {

    fileQueue = fileQueue.filter(entry => entry.id !== id);
    renderFileQueue();
}


function renderFileQueue(skippedCount = 0) {

    const listElement = document.getElementById("file-queue-list");
    const createFilesButton = document.getElementById("create-playlists-from-files-button");

    listElement.innerHTML = "";

    for (const entry of fileQueue) {

        const item = document.createElement("li");
        item.className = `file-queue-item file-queue-item--${entry.status}`;

        let statusText;

        if (entry.status === "pending") {
            statusText = `${entry.trackIds.length} gültige Titel` +
                (entry.invalidCount > 0 ? `, ${entry.invalidCount} ungültig` : "");
        } else if (entry.status === "creating") {
            statusText = entry.progressText || "wird erstellt...";
        } else if (entry.status === "done") {
            statusText = "✅ Playlist erstellt";
        } else {
            statusText = `❌ ${entry.errorMessage || "Fehler"}`;
        }

        item.innerHTML = `
            <span class="file-queue-item__name">
                ${entry.fileName} → <strong>${entry.playlistName}</strong>
            </span>
            <span class="file-queue-item__status">${statusText}</span>
        `;

        if (entry.status === "pending") {

            const removeButton = document.createElement("button");
            removeButton.type = "button";
            removeButton.textContent = "Entfernen";
            removeButton.className = "file-queue-item__remove";
            removeButton.addEventListener("click", () => removeFileFromQueue(entry.id));

            item.appendChild(removeButton);
        }

        if (entry.status === "done" && entry.playlistUrl) {

            const link = document.createElement("a");
            link.href = entry.playlistUrl;
            link.target = "_blank";
            link.rel = "noopener";
            link.textContent = "In Spotify öffnen";
            link.className = "file-queue-item__link";

            item.appendChild(link);
        }

        listElement.appendChild(item);
    }

    const hasPendingFiles = fileQueue.some(entry => entry.status === "pending");
    createFilesButton.hidden = !hasPendingFiles;

    const resultsElement = document.getElementById("file-playlist-results");

    if (skippedCount > 0) {
        resultsElement.textContent =
            `${skippedCount} Datei(en) wurden ignoriert (nur .txt-Dateien werden unterstützt).`;
    } else if (fileQueue.length === 0) {
        resultsElement.textContent = "";
    }
}


// Verarbeitet die Warteschlange sequentiell: für jede Datei wird
// eine eigene Playlist erstellt, bevor die nächste Datei dran ist
// (nacheinander statt parallel, um kein Rate Limit auszulösen).
async function createPlaylistsFromFiles() {

    const createFilesButton = document.getElementById("create-playlists-from-files-button");

    if (createFilesButton.disabled) {
        return;
    }

    createFilesButton.disabled = true;

    const pendingEntries = fileQueue.filter(entry => entry.status === "pending");

    for (const entry of pendingEntries) {

        if (entry.trackIds.length === 0) {

            entry.status = "error";
            entry.errorMessage = "Keine gültigen Titel in der Datei gefunden.";
            renderFileQueue();
            continue;
        }

        entry.status = "creating";
        entry.progressText = "wird erstellt...";
        renderFileQueue();

        try {

            const { playlist, requestedCount, actualTrackCount } =
                await createPlaylistFromTracks(
                    entry.playlistName,
                    entry.trackIds,
                    (text) => {
                        entry.progressText = text;
                        renderFileQueue();
                    }
                );

            entry.status = "done";
            entry.playlistUrl = playlist.external_urls.spotify;
            entry.actualTrackCount = actualTrackCount;
            entry.requestedCount = requestedCount;

        } catch (error) {

            console.error(`Playlist für Datei "${entry.fileName}" fehlgeschlagen:`, error);

            entry.status = "error";
            entry.errorMessage = error.message || "Unbekannter Fehler";

            // Bei abgelaufener Sitzung Login-Status aktualisieren und
            // die restlichen Dateien nicht weiter versuchen.
            if (error.message?.includes("Sitzung abgelaufen") ||
                error.message?.includes("Nicht mit Spotify verbunden")) {

                await updateLoginStatus();
                renderFileQueue();
                break;
            }
        }

        renderFileQueue();
    }

    createFilesButton.disabled = false;
}


// --------------------------------------------------
// Drag & Drop einrichten
// --------------------------------------------------

function setupFileDropZone() {

    const dropZone = document.getElementById("file-drop-zone");
    const fileInput = document.getElementById("file-input");

    if (!dropZone || !fileInput) {
        console.warn("Drop-Zone-Elemente wurden im HTML nicht gefunden - Datei-Upload ist deaktiviert.");
        return;
    }

    // Klick auf die Drop-Zone öffnet den normalen Datei-Dialog
    // (Fallback für alle, die nicht per Drag & Drop arbeiten wollen
    // oder können, z. B. Tastaturnutzung oder mobile Geräte).
    dropZone.addEventListener("click", () => fileInput.click());

    dropZone.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            fileInput.click();
        }
    });

    fileInput.addEventListener("change", async (event) => {
        await addFilesToQueue(event.target.files);
        fileInput.value = ""; // erlaubt erneutes Auswählen derselben Datei
    });

    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, (event) => {
            event.preventDefault();
            event.stopPropagation();
            dropZone.classList.add("drop-zone--active");
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, (event) => {
            event.preventDefault();
            event.stopPropagation();
            dropZone.classList.remove("drop-zone--active");
        });
    });

    dropZone.addEventListener("drop", async (event) => {

        const droppedFiles = event.dataTransfer?.files;

        if (droppedFiles && droppedFiles.length > 0) {
            await addFilesToQueue(droppedFiles);
        }
    });
}


// --------------------------------------------------
// Event-Listener
// --------------------------------------------------

// Registriert einen Click-Handler nur, wenn das Element tatsächlich
// existiert. So bricht ein einzelnes fehlendes/falsch benanntes
// Element (z. B. durch ein veraltetes HTML) nicht die komplette
// restliche Initialisierung ab - es gibt stattdessen eine klare
// Warnung in der Konsole.
function addClickListener(elementId, handler) {

    const element = document.getElementById(elementId);

    if (!element) {
        console.warn(`Element mit id="${elementId}" wurde im HTML nicht gefunden.`);
        return;
    }

    element.addEventListener("click", handler);
}

addClickListener("login-button", loginWithSpotify);
addClickListener("validate-button", validateTracks);
addClickListener("create-playlist-button", createPlaylist);
addClickListener("create-playlists-from-files-button", createPlaylistsFromFiles);

// --------------------------------------------------
// Anwendung starten
// --------------------------------------------------

setupFileDropZone();
handleAuthorizationCallback();
updateLoginStatus();
