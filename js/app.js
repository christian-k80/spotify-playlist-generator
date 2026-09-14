// Spotify Playlist Generator
// OAuth 2.0 mit PKCE + Refresh-Token + CSRF-Schutz (state)
// + Playlist-Erstellung aus TXT-Dateien per Drag & Drop
// + Public/Private-Toggle, Fortschrittsanzeige, Clear-All

const CLIENT_ID = "b7a1cad39a6e4ec6b3a82511b6b5e682";

const REDIRECT_URI =
    "https://christian-k80.github.io/spotify-playlist-generator/";

const SCOPES = [
    "playlist-modify-public",
    "playlist-modify-private",
    "playlist-read-private",
    "playlist-read-collaborative"
];

// Anzahl Titel pro Seite beim paginierten Abrufen einer Playlist
// für den Export.
const EXPORT_PAGE_SIZE = 100;

// Spaltenreihenfolge der exportierten TXT-Datei. "Popularity",
// "Record Label" und alle Audio-Feature-Spalten (Danceability,
// Energy, Key, Loudness, Mode, Speechiness, Acousticness,
// Instrumentalness, Liveness, Valence, Tempo) fehlen bewusst - die
// zugehörigen Spotify-Endpunkte/Felder wurden 2024/2026 entfernt
// und liefern für keine App mehr Daten.
const EXPORT_COLUMNS = [
    "Track URI",
    "Track Name",
    "Album Name",
    "Artist Name(s)",
    "Release Date",
    "Duration (ms)",
    "Explicit",
    "Genres"
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

// Wie lange der grüne "Erfolgs-Puls" auf einer Card sichtbar bleibt.
const SUCCESS_PULSE_DURATION_MS = 900;


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
        throw new Error("PKCE code verifier missing.");
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
        throw new Error("Login failed.");
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
            "Login cancelled.";

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
            "Security check failed. Please log in again.";

        clearAllAuthData();
        window.history.replaceState({}, document.title, REDIRECT_URI);
        return;
    }

    sessionStorage.removeItem("spotify_oauth_state");

    try {

        document.getElementById("login-status").textContent =
            "Connecting...";

        await exchangeCodeForToken(code);

        window.history.replaceState({}, document.title, REDIRECT_URI);

        await updateLoginStatus();

    } catch (error) {

        console.error(error);

        document.getElementById("login-status").textContent =
            "Login failed.";

        clearAllAuthData();
    }
}


// Lädt das Profil des aktuell verbundenen Nutzers. display_name ist
// ohne zusätzlichen Scope verfügbar (im Gegensatz zu z. B. country
// oder email, die user-read-private/-email voraussetzen).
async function fetchCurrentUserProfile() {

    try {

        const response = await fetchSpotifyApi(
            "https://api.spotify.com/v1/me",
            { method: "GET" }
        );

        if (!response.ok) {
            return null;
        }

        return await response.json();

    } catch (error) {

        console.error("Profil konnte nicht geladen werden:", error);
        return null;
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

        const profile = await fetchCurrentUserProfile();
        const displayName = profile?.display_name;

        status.textContent = displayName ?
            `Connected as ${displayName}.` :
            "Connected. Let's go.";

        button.textContent = "Disconnect";
        button.disabled = false;
        button.dataset.connected = "true";

    } else {

        status.textContent = "Not connected yet.";
        button.textContent = "Connect with Spotify";
        button.disabled = false;
        button.dataset.connected = "false";
    }
}


// Trennt die Verbindung: löscht alle lokal gespeicherten Tokens.
// Der Access Token bei Spotify selbst wird dadurch nicht widerrufen
// (Spotify bietet dafür keinen öffentlichen Endpunkt) - beim
// nächsten "Connect" fragt Spotify ggf. erneut nach Zustimmung.
function disconnectFromSpotify() {

    clearAllAuthData();
    updateLoginStatus();
}


// Reagiert auf den Klick des Login-Buttons je nach aktuellem
// Verbindungsstatus: verbunden -> trennen, sonst -> Login starten.
async function handleLoginButtonClick() {

    const button = document.getElementById("login-button");

    if (button.dataset.connected === "true") {
        disconnectFromSpotify();
    } else {
        await loginWithSpotify();
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
// Playlist-Export
// --------------------------------------------------

// Erkennt eine Playlist-ID aus einer Spotify-URI, einer
// open.spotify.com-URL oder einer direkt eingegebenen ID.
function extractPlaylistId(input) {

    const value = input.trim();

    const uriMatch = value.match(/^spotify:playlist:([a-zA-Z0-9]+)$/);

    if (uriMatch) {
        return uriMatch[1];
    }

    try {

        const url = new URL(value);

        if (url.hostname === "open.spotify.com") {

            const pathParts = url.pathname.split("/");
            const playlistIndex = pathParts.indexOf("playlist");

            if (playlistIndex !== -1 && pathParts[playlistIndex + 1]) {
                return pathParts[playlistIndex + 1];
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


// Entfernt Semikolons und Zeilenumbrüche aus einem Feldwert, damit
// die Spaltenstruktur der TXT-Datei nicht kaputtgeht.
function sanitizeExportField(value) {

    if (value === null || value === undefined) {
        return "";
    }

    return String(value).replace(/[;\r\n]+/g, ",").trim();
}


// Entfernt Zeichen aus einem Playlist-Namen, die in Dateinamen auf
// den meisten Betriebssystemen nicht erlaubt sind.
function sanitizeFileName(name) {

    const cleaned = name.replace(/[\\/:*?"<>|]/g, "_").trim();

    return cleaned || "playlist";
}


function triggerTextFileDownload(fileName, content) {

    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
}


// Kernfunktion des Exports, unabhängig von der aufrufenden Karte:
// lädt Playlist-Metadaten, alle Titel (paginiert) und die Genres
// pro einzigartigem Künstler, baut die TXT-Datei und stößt den
// Download an. onStatus(text) liefert Fortschrittstexte,
// onProgress(fraction) einen Wert zwischen 0 und 1 für Progress-Bars.
async function runPlaylistExport(playlistId, { onStatus, onProgress } = {}) {

    const notifyStatus = (text) => { if (onStatus) onStatus(text); };
    const notifyProgress = (fraction) => { if (onProgress) onProgress(fraction); };

    const notifyWaiting = (waitSeconds) => {
        notifyStatus(`Spotify's hitting the brakes – waiting ${waitSeconds}s...`);
    };

    // ------------------------------------------
    // 1. Playlist-Metadaten laden (für den Dateinamen)
    // ------------------------------------------

    const playlistResponse = await fetchSpotifyApi(
        `https://api.spotify.com/v1/playlists/${playlistId}`,
        { method: "GET" },
        notifyWaiting
    );

    if (!playlistResponse.ok) {
        throw new Error(
            await buildApiErrorMessage(playlistResponse, "Could not load playlist")
        );
    }

    const playlistData = await playlistResponse.json();
    const playlistName = playlistData.name || "playlist";

    // ------------------------------------------
    // 2. Alle Titel paginiert laden
    // ------------------------------------------

    const tracks = [];
    let offset = 0;
    let total = null;

    do {

        const itemsResponse = await fetchSpotifyApi(
            `https://api.spotify.com/v1/playlists/${playlistId}/items?limit=${EXPORT_PAGE_SIZE}&offset=${offset}`,
            { method: "GET" },
            notifyWaiting
        );

        if (!itemsResponse.ok) {
            throw new Error(
                await buildApiErrorMessage(itemsResponse, "Could not load tracks")
            );
        }

        const itemsData = await itemsResponse.json();
        total = itemsData.total ?? total ?? 0;

        for (const item of itemsData.items || []) {
            if (item.track) {
                tracks.push(item.track);
            }
        }

        offset += EXPORT_PAGE_SIZE;

        // Das Laden der Titel macht die erste Hälfte des Fortschritts
        // aus, der Genre-Abgleich pro Künstler danach die zweite.
        const loadFraction = total > 0 ? Math.min(tracks.length / total, 1) : 1;
        notifyProgress(loadFraction * 0.5);

        notifyStatus(`Loading tracks... (${tracks.length} / ${total ?? "?"})`);

    } while (total !== null && offset < total);

    // ------------------------------------------
    // 3. Genres pro einzigartigem Künstler laden
    // ------------------------------------------

    // Seit Februar 2026 gibt es keinen Batch-Endpunkt für mehrere
    // Künstler mehr ("Get Several Artists" wurde entfernt) - jeder
    // einzigartige Künstler muss einzeln abgefragt werden.
    const uniqueArtistIds = [...new Set(
        tracks.flatMap(track => (track.artists || []).map(artist => artist.id).filter(Boolean))
    )];

    const genresByArtistId = new Map();

    for (let i = 0; i < uniqueArtistIds.length; i++) {

        const artistId = uniqueArtistIds[i];

        const artistResponse = await fetchSpotifyApi(
            `https://api.spotify.com/v1/artists/${artistId}`,
            { method: "GET" },
            notifyWaiting
        );

        genresByArtistId.set(
            artistId,
            artistResponse.ok ? (await artistResponse.json()).genres || [] : []
        );

        const genreFraction = uniqueArtistIds.length > 0 ?
            (i + 1) / uniqueArtistIds.length :
            1;

        notifyProgress(0.5 + genreFraction * 0.5);

        notifyStatus(`Fetching genres... (${i + 1} / ${uniqueArtistIds.length} artists)`);
    }

    // ------------------------------------------
    // 4. TXT-Datei zusammenbauen und herunterladen
    // ------------------------------------------

    const lines = [EXPORT_COLUMNS.join(";")];

    for (const track of tracks) {

        const artistNames = (track.artists || [])
            .map(artist => artist.name)
            .join(", ");

        const genres = [...new Set(
            (track.artists || []).flatMap(
                artist => genresByArtistId.get(artist.id) || []
            )
        )].join(", ");

        const row = [
            track.uri || "",
            track.name || "",
            track.album?.name || "",
            artistNames,
            track.album?.release_date || "",
            track.duration_ms ?? "",
            track.explicit ? "true" : "false",
            genres
        ].map(sanitizeExportField);

        lines.push(row.join(";"));
    }

    const fileName = `${sanitizeFileName(playlistName)}.txt`;

    triggerTextFileDownload(fileName, lines.join("\n"));

    return { trackCount: tracks.length, fileName };
}


// UI-Wrapper für die "Export"-Karte (Playlist per Link/URI/ID).
async function exportPlaylist() {

    const exportButton = document.getElementById("export-playlist-button");

    if (exportButton.disabled) {
        return;
    }

    const input = document.getElementById("export-playlist-input").value;
    const result = document.getElementById("export-result");
    const progressBar = document.getElementById("export-progress");

    const playlistId = extractPlaylistId(input);

    if (!playlistId) {
        result.textContent = "That doesn't look like a playlist link, URI, or ID.";
        return;
    }

    exportButton.disabled = true;
    progressBar.hidden = false;
    progressBar.value = 0;
    result.textContent = "Loading playlist...";

    try {

        const { trackCount, fileName } = await runPlaylistExport(playlistId, {
            onStatus: (text) => { result.textContent = text; },
            onProgress: (fraction) => { progressBar.value = Math.round(fraction * 100); }
        });

        result.textContent = `Done. ${trackCount} tracks exported to "${fileName}".`;

    } catch (error) {

        console.error(error);

        result.textContent = error.message || "Export didn't work out.";

        await updateLoginStatus();

    } finally {

        exportButton.disabled = false;
        progressBar.hidden = true;
    }
}


// --------------------------------------------------
// "My Playlists" - alle Playlisten des Nutzers auflisten und
// einzeln exportieren
// --------------------------------------------------

let myPlaylists = [];

async function loadMyPlaylists() {

    const loadButton = document.getElementById("load-playlists-button");
    const resultElement = document.getElementById("my-playlists-result");

    if (loadButton.disabled) {
        return;
    }

    loadButton.disabled = true;
    resultElement.textContent = "Loading your playlists...";
    myPlaylists = [];
    renderMyPlaylists();

    try {

        const collected = [];
        let url = "https://api.spotify.com/v1/me/playlists?limit=50";

        while (url) {

            const response = await fetchSpotifyApi(
                url,
                { method: "GET" },
                (waitSeconds) => {
                    resultElement.textContent = `Spotify's hitting the brakes – waiting ${waitSeconds}s...`;
                }
            );

            if (!response.ok) {
                throw new Error(
                    await buildApiErrorMessage(response, "Could not load playlists")
                );
            }

            const data = await response.json();

            for (const item of data.items || []) {

                if (!item) {
                    continue;
                }

                collected.push({
                    id: item.id,
                    name: item.name || "Untitled playlist",
                    trackCount: item.tracks?.total ?? item.items?.total ?? null,
                    status: "idle"
                });
            }

            url = data.next || null;
        }

        myPlaylists = collected;

        resultElement.textContent = myPlaylists.length === 0 ?
            "No playlists found on this account." :
            "";

    } catch (error) {

        console.error(error);

        resultElement.textContent = error.message || "Could not load your playlists.";

        await updateLoginStatus();

    } finally {

        loadButton.disabled = false;
        renderMyPlaylists();
    }
}


function renderMyPlaylists() {

    const listElement = document.getElementById("my-playlists-list");

    listElement.innerHTML = "";

    for (const entry of myPlaylists) {

        const item = document.createElement("li");
        const stateClass = entry.status === "idle" ? "pending" : entry.status;
        item.className = `file-queue-item file-queue-item--${stateClass}`;

        let statusText = "";
        let progressHtml = "";

        if (entry.status === "idle") {

            statusText = entry.trackCount !== null ? `${entry.trackCount} tracks` : "";

        } else if (entry.status === "creating") {

            statusText = entry.progressText || "exporting...";

            progressHtml = `
                <progress
                    class="file-queue-item__progress"
                    value="${entry.progressPercent ?? 0}"
                    max="100"
                ></progress>
            `;

        } else if (entry.status === "done") {

            statusText = "✅ Exported";

        } else if (entry.status === "error") {

            statusText = `❌ ${entry.errorMessage || "Error"}`;
        }

        item.innerHTML = `
            <span class="file-queue-item__name">${escapeHtml(entry.name)}</span>
            <span class="file-queue-item__status">${escapeHtml(statusText)}</span>
            ${progressHtml}
        `;

        if (entry.status !== "creating") {

            const exportButton = document.createElement("button");
            exportButton.type = "button";
            exportButton.className = "file-queue-item__action";
            exportButton.textContent = entry.status === "done" ? "Export again" : "Export";
            exportButton.addEventListener("click", () => exportMyPlaylist(entry.id));

            item.appendChild(exportButton);
        }

        listElement.appendChild(item);
    }
}


async function exportMyPlaylist(playlistId) {

    const entry = myPlaylists.find(playlist => playlist.id === playlistId);

    if (!entry || entry.status === "creating") {
        return;
    }

    entry.status = "creating";
    entry.progressText = "exporting...";
    entry.progressPercent = 0;
    renderMyPlaylists();

    try {

        await runPlaylistExport(playlistId, {
            onStatus: (text) => {
                entry.progressText = text;
                renderMyPlaylists();
            },
            onProgress: (fraction) => {
                entry.progressPercent = Math.round(fraction * 100);
                renderMyPlaylists();
            }
        });

        entry.status = "done";
        entry.errorMessage = null;

        pulseCard(document.getElementById("my-playlists-list")?.closest(".card"));

    } catch (error) {

        console.error(`Export für Playlist "${entry.name}" fehlgeschlagen:`, error);

        entry.status = "error";
        entry.errorMessage = error.message || "Unknown error";

        if (error.message?.includes("Session expired") ||
            error.message?.includes("Not connected")) {

            await updateLoginStatus();
        }
    }

    renderMyPlaylists();
}


// Escaped Sonderzeichen, bevor ein Wert in ein innerHTML-Template
// eingesetzt wird. Ohne das könnte z. B. eine .txt-Datei mit einem
// bösartigen Dateinamen (z. B. enthält "<img onerror=...>") Code im
// Kontext dieser Seite ausführen und so an die in sessionStorage
// gespeicherten Spotify-Tokens gelangen.
function escapeHtml(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


// --------------------------------------------------
// Hilfsfunktion: Card kurz grün aufleuchten lassen
// --------------------------------------------------

function pulseCard(cardElement) {

    if (!cardElement) {
        return;
    }

    cardElement.classList.remove("card--success-pulse");

    // Erzwingt einen Reflow, damit die Animation auch dann neu
    // startet, wenn die Klasse kurz zuvor schon einmal gesetzt war.
    void cardElement.offsetWidth;

    cardElement.classList.add("card--success-pulse");

    setTimeout(
        () => cardElement.classList.remove("card--success-pulse"),
        SUCCESS_PULSE_DURATION_MS
    );
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
            throw new Error("Timeout: Spotify didn't respond in time.");
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
            throw new Error("Rate limit: too many retries, aborting.");
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
        throw new Error("Not connected. Log in first.");
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
            throw new Error("Session expired. Reconnect.");
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
        result.textContent = "Nothing in here yet.";
        return;
    }

    const { trackIds, invalidEntries, duplicateCount } = parseTrackLines(input);

    let message = `${trackIds.length + duplicateCount} tracks found.`;

    if (duplicateCount > 0) {
        message += ` ${duplicateCount} of them duplicates.`;
    }

    if (invalidEntries.length > 0) {
        message += ` ${invalidEntries.length} line(s) invalid – not a Spotify ID, URI, or URL.`;
    }

    message += " Whether the tracks actually exist on Spotify shows up when you create the playlist.";

    result.textContent = message;
}


// --------------------------------------------------
// Kernfunktion: Eine Playlist aus Track-IDs erstellen
// --------------------------------------------------

// onStatus(text, fraction) wird für Fortschritts-/Wartemeldungen
// aufgerufen. "fraction" ist eine Zahl zwischen 0 und 1 (Fortschritt
// beim Hinzufügen der Titel) oder null, wenn sich der Fortschritt
// durch diesen Zwischenschritt nicht ändert (z. B. während einer
// Rate-Limit-Wartezeit) - der Aufrufer soll den zuletzt bekannten
// Fortschrittswert dann einfach unverändert lassen.
async function createPlaylistFromTracks(playlistName, trackIds, isPublic, onStatus) {

    const notify = (text, fraction = null) => {
        if (onStatus) onStatus(text, fraction);
    };

    // ------------------------------------------
    // 1. Playlist erstellen
    // ------------------------------------------

    notify(`"${playlistName}" is coming together... (0 / ${trackIds.length})`, 0);

    const playlistResponse = await fetchSpotifyApi(
        "https://api.spotify.com/v1/me/playlists",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: playlistName,
                public: isPublic,
                collaborative: false,
                description: "Created with the Spotify Playlist Generator"
            })
        },
        (waitSeconds) => notify(`Spotify's hitting the brakes – waiting ${waitSeconds}s...`)
    );

    if (!playlistResponse.ok) {

        const baseMessage = await buildApiErrorMessage(playlistResponse, "Playlist didn't go through");

        // 403 beim Erstellen einer Playlist bedeutet so gut wie immer,
        // dass das aktuell verbundene Spotify-Konto nicht in der
        // Nutzerliste der App im Spotify Developer Dashboard steht
        // (Development Mode erlaubt nur freigeschaltete Konten) - nicht
        // ein Fehler in dieser App.
        if (playlistResponse.status === 403) {
            throw new Error(
                `${baseMessage} — this Spotify account may not be added to the app's allowed users in the Spotify Developer Dashboard (Settings → User Management).`
            );
        }

        throw new Error(baseMessage);
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
            (waitSeconds) => notify(`Spotify's hitting the brakes – waiting ${waitSeconds}s...`)
        );

        if (!tracksResponse.ok) {
            throw new Error(
                await buildApiErrorMessage(tracksResponse, "Tracks wouldn't go in")
            );
        }

        addedCount += batch.length;

        const fraction = trackUris.length > 0 ? addedCount / trackUris.length : 1;

        notify(`"${playlistName}" is coming together... (${addedCount} / ${trackUris.length})`, fraction);
    }

    // ------------------------------------------
    // 3. Tatsächliche Titelanzahl prüfen
    // ------------------------------------------

    let actualTrackCount = null;

    const playlistDetailsResponse = await fetchSpotifyApi(
        `https://api.spotify.com/v1/playlists/${playlist.id}`,
        { method: "GET" },
        (waitSeconds) => notify(`Spotify's hitting the brakes – waiting ${waitSeconds}s...`)
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
    const isPublic = document.getElementById("playlist-public-toggle").checked;
    const input = document.getElementById("track-input").value;
    const result = document.getElementById("playlist-result");
    const progressBar = document.getElementById("playlist-progress");

    if (!playlistName) {
        result.textContent = "Give it a name first.";
        return;
    }

    if (playlistName.length > MAX_PLAYLIST_NAME_LENGTH) {
        result.textContent =
            `Too long. Max ${MAX_PLAYLIST_NAME_LENGTH} characters.`;
        return;
    }

    const { trackIds } = parseTrackLines(input);

    if (trackIds.length === 0) {
        result.textContent = "No valid tracks found.";
        return;
    }

    createButton.disabled = true;
    progressBar.hidden = false;
    progressBar.value = 0;

    try {

        const { playlist, requestedCount, actualTrackCount } =
            await createPlaylistFromTracks(
                playlistName,
                trackIds,
                isPublic,
                (text, fraction) => {
                    result.textContent = text;
                    if (fraction !== null && fraction !== undefined) {
                        progressBar.value = Math.round(fraction * 100);
                    }
                }
            );

        result.innerHTML = buildPlaylistResultHtml(playlist, requestedCount, actualTrackCount);

        pulseCard(result.closest(".card"));

    } catch (error) {

        console.error(error);

        result.textContent =
            error.message || "Playlist didn't come together.";

        await updateLoginStatus();

    } finally {

        createButton.disabled = false;
        progressBar.hidden = true;
    }
}


function buildPlaylistResultHtml(playlist, requestedCount, actualTrackCount) {

    const countMatches = actualTrackCount === requestedCount;

    let statusHtml;

    if (actualTrackCount === null) {

        statusHtml = `
            <p>
                ${requestedCount} tracks sent. Couldn't fetch the actual
                count – better check Spotify yourself.
            </p>
        `;

    } else if (countMatches) {

        statusHtml = `
            <p>
                All ${actualTrackCount} tracks are in.
            </p>
        `;

    } else {

        const missingCount = requestedCount - actualTrackCount;

        statusHtml = `
            <p>
                ${actualTrackCount} of ${requestedCount} tracks are in.
                ${missingCount} missing – usually because the track ID
                doesn't exist on Spotify (anymore).
            </p>
        `;
    }

    return `
        <p>
            <strong>"${escapeHtml(playlist.name)}" is live.</strong>
        </p>

        ${statusHtml}

        <p>
            <a
                href="${escapeHtml(playlist.external_urls.spotify)}"
                target="_blank"
                rel="noopener"
            >
                Open in Spotify
            </a>
        </p>
    `;
}


// --------------------------------------------------
// Playlist-Erstellung aus TXT-Dateien (Drag & Drop)
// --------------------------------------------------

let fileQueue = [];

// Merkt sich, welche Queue-Einträge bereits einmal gerendert wurden,
// damit die Enter-Animation nur bei neu hinzugefügten Dateien läuft
// und nicht bei jedem Fortschritts-Update erneut abspielt.
let renderedFileIds = new Set();

function generateQueueId() {
    return (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);
}


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
            status: "pending", // pending | creating | done | error
            progressPercent: 0
        });
    }

    renderFileQueue(skippedCount);
}


function removeFileFromQueue(id) {

    fileQueue = fileQueue.filter(entry => entry.id !== id);
    renderFileQueue();
}


// Leert die komplette Warteschlange (unabhängig vom Status der
// einzelnen Einträge). Bereits erstellte Playlists bei Spotify sind
// davon nicht betroffen - es wird nur die lokale Anzeige geleert.
function clearFileQueue() {

    fileQueue = [];
    renderedFileIds = new Set();
    renderFileQueue();
}


function renderFileQueue(skippedCount = 0) {

    const listElement = document.getElementById("file-queue-list");
    const createFilesButton = document.getElementById("create-playlists-from-files-button");
    const clearButton = document.getElementById("clear-file-queue-button");
    const emptyState = document.getElementById("file-queue-empty");

    listElement.innerHTML = "";

    for (const entry of fileQueue) {

        const item = document.createElement("li");
        item.className = `file-queue-item file-queue-item--${entry.status}`;

        if (!renderedFileIds.has(entry.id)) {
            item.classList.add("file-queue-item--enter");
        }

        let statusText;
        let progressHtml = "";

        if (entry.status === "pending") {

            statusText = `${entry.trackIds.length} tracks in` +
                (entry.invalidCount > 0 ? `, ${entry.invalidCount} out` : "");

        } else if (entry.status === "creating") {

            statusText = entry.progressText || "running...";

            progressHtml = `
                <progress
                    class="file-queue-item__progress"
                    value="${entry.progressPercent ?? 0}"
                    max="100"
                ></progress>
            `;

        } else if (entry.status === "done") {

            statusText = "✅ Done";

        } else {

            statusText = `❌ ${entry.errorMessage || "Error"}`;
        }

        item.innerHTML = `
            <span class="file-queue-item__name">
                ${escapeHtml(entry.fileName)} → <strong>${escapeHtml(entry.playlistName)}</strong>
            </span>
            <span class="file-queue-item__status">${escapeHtml(statusText)}</span>
            ${progressHtml}
        `;

        if (entry.status === "pending") {

            const removeButton = document.createElement("button");
            removeButton.type = "button";
            removeButton.className = "file-queue-item__remove";
            removeButton.setAttribute("aria-label", `Remove ${entry.fileName} from the queue`);
            removeButton.title = "Remove";

            removeButton.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M3 6h18"></path>
                    <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                    <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path>
                </svg>
            `;

            removeButton.addEventListener("click", () => removeFileFromQueue(entry.id));

            item.appendChild(removeButton);
        }

        if (entry.status === "done" && entry.playlistUrl) {

            const link = document.createElement("a");
            link.href = entry.playlistUrl;
            link.target = "_blank";
            link.rel = "noopener";
            link.textContent = "Open in Spotify";
            link.className = "file-queue-item__link";

            item.appendChild(link);
        }

        listElement.appendChild(item);
    }

    renderedFileIds = new Set(fileQueue.map(entry => entry.id));

    const hasPendingFiles = fileQueue.some(entry => entry.status === "pending");
    createFilesButton.hidden = !hasPendingFiles;

    clearButton.hidden = fileQueue.length === 0;
    emptyState.hidden = fileQueue.length > 0;

    const resultsElement = document.getElementById("file-playlist-results");

    if (skippedCount > 0) {
        resultsElement.textContent =
            `${skippedCount} file(s) skipped – only .txt counts.`;
    } else if (fileQueue.length === 0) {
        resultsElement.textContent = "";
    }
}


async function createPlaylistsFromFiles() {

    const createFilesButton = document.getElementById("create-playlists-from-files-button");
    const clearButton = document.getElementById("clear-file-queue-button");
    const isPublic = document.getElementById("files-public-toggle").checked;
    const filesCard = document.getElementById("file-drop-zone").closest(".card");

    if (createFilesButton.disabled) {
        return;
    }

    createFilesButton.disabled = true;
    clearButton.disabled = true;

    const pendingEntries = fileQueue.filter(entry => entry.status === "pending");

    for (const entry of pendingEntries) {

        if (entry.trackIds.length === 0) {

            entry.status = "error";
            entry.errorMessage = "No valid tracks in this file.";
            renderFileQueue();
            continue;
        }

        entry.status = "creating";
        entry.progressText = "running...";
        entry.progressPercent = 0;
        renderFileQueue();

        try {

            const { playlist, requestedCount, actualTrackCount } =
                await createPlaylistFromTracks(
                    entry.playlistName,
                    entry.trackIds,
                    isPublic,
                    (text, fraction) => {
                        entry.progressText = text;
                        if (fraction !== null && fraction !== undefined) {
                            entry.progressPercent = Math.round(fraction * 100);
                        }
                        renderFileQueue();
                    }
                );

            entry.status = "done";
            entry.playlistUrl = playlist.external_urls.spotify;
            entry.actualTrackCount = actualTrackCount;
            entry.requestedCount = requestedCount;

            pulseCard(filesCard);

        } catch (error) {

            console.error(`Playlist für Datei "${entry.fileName}" fehlgeschlagen:`, error);

            entry.status = "error";
            entry.errorMessage = error.message || "Unknown error";

            if (error.message?.includes("Session expired") ||
                error.message?.includes("Not connected")) {

                await updateLoginStatus();
                renderFileQueue();
                break;
            }
        }

        renderFileQueue();
    }

    createFilesButton.disabled = false;
    clearButton.disabled = false;
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
// Panel-Navigation (Swipe / Pfeile / Punkte / Tastatur)
// --------------------------------------------------

function setupPanelNavigation() {

    const panelsContainer = document.getElementById("panels");
    const dotsContainer = document.getElementById("panel-dots");
    const prevButton = document.getElementById("panel-prev");
    const nextButton = document.getElementById("panel-next");

    if (!panelsContainer || !dotsContainer || !prevButton || !nextButton) {
        console.warn("Panel-Navigation: benötigte Elemente fehlen im HTML.");
        return;
    }

    const panels = Array.from(panelsContainer.querySelectorAll(".panel"));

    panels.forEach((panel, index) => {

        const dot = document.createElement("button");
        dot.type = "button";
        dot.className = "panel-dot";
        dot.setAttribute("aria-label", panel.dataset.panelLabel || `Panel ${index + 1}`);
        dot.addEventListener("click", () => scrollToPanel(index));

        dotsContainer.appendChild(dot);
    });

    const dots = Array.from(dotsContainer.querySelectorAll(".panel-dot"));

    function getCurrentIndex() {
        const width = panelsContainer.clientWidth || 1;
        return Math.round(panelsContainer.scrollLeft / width);
    }

    // Setzt den aktiven Zustand von Punkten und Pfeil-Buttons direkt,
    // unabhängig von "scroll"-Events. Bei einem Klick auf einen Punkt
    // oder Pfeil soll die Farbe sofort wechseln, nicht erst wenn der
    // (in manchen Browsern unzuverlässig feuernde) Scroll-Event der
    // Smooth-Scroll-Animation eintrifft.
    function setActiveIndex(index) {

        dots.forEach((dot, dotIndex) => {
            dot.classList.toggle("panel-dot--active", dotIndex === index);
        });

        prevButton.disabled = index === 0;
        nextButton.disabled = index === panels.length - 1;
    }

    function scrollToPanel(index) {

        const clampedIndex = Math.max(0, Math.min(index, panels.length - 1));

        panelsContainer.scrollTo({
            left: clampedIndex * panelsContainer.clientWidth,
            behavior: "smooth"
        });

        setActiveIndex(clampedIndex);
    }

    function updateActiveState() {
        setActiveIndex(getCurrentIndex());
    }

    // Scroll-Events feuern beim Wischen sehr häufig - per
    // requestAnimationFrame gebündelt, um nicht bei jedem Pixel
    // Fortschritt Dots/Buttons neu zu berechnen.
    let scrollUpdateScheduled = false;

    panelsContainer.addEventListener("scroll", () => {

        if (scrollUpdateScheduled) {
            return;
        }

        scrollUpdateScheduled = true;

        requestAnimationFrame(() => {
            updateActiveState();
            scrollUpdateScheduled = false;
        });
    });

    window.addEventListener("resize", updateActiveState);

    prevButton.addEventListener("click", () => scrollToPanel(getCurrentIndex() - 1));
    nextButton.addEventListener("click", () => scrollToPanel(getCurrentIndex() + 1));

    // Pfeiltasten nur außerhalb von Eingabefeldern abfangen, sonst
    // könnte man z. B. im Textfeld nicht mehr mit den Pfeiltasten
    // den Cursor bewegen.
    document.addEventListener("keydown", (event) => {

        const activeTag = document.activeElement?.tagName;
        const isTypingContext = activeTag === "INPUT" || activeTag === "TEXTAREA";

        if (isTypingContext) {
            return;
        }

        if (event.key === "ArrowLeft") {
            scrollToPanel(getCurrentIndex() - 1);
        } else if (event.key === "ArrowRight") {
            scrollToPanel(getCurrentIndex() + 1);
        }
    });

    updateActiveState();
}


// --------------------------------------------------
// Event-Listener
// --------------------------------------------------

function addClickListener(elementId, handler) {

    const element = document.getElementById(elementId);

    if (!element) {
        console.warn(`Element mit id="${elementId}" wurde im HTML nicht gefunden.`);
        return;
    }

    element.addEventListener("click", handler);
}

addClickListener("login-button", handleLoginButtonClick);
addClickListener("validate-button", validateTracks);
addClickListener("create-playlist-button", createPlaylist);
addClickListener("create-playlists-from-files-button", createPlaylistsFromFiles);
addClickListener("clear-file-queue-button", clearFileQueue);
addClickListener("export-playlist-button", exportPlaylist);
addClickListener("load-playlists-button", loadMyPlaylists);

// --------------------------------------------------
// Anwendung starten
// --------------------------------------------------

setupFileDropZone();
setupPanelNavigation();
handleAuthorizationCallback();
updateLoginStatus();
