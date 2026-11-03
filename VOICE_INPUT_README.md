# Voice input (Groq Whisper)

The microphone now uses browser MediaRecorder and server-side Groq Whisper only. Browser live SpeechRecognition was removed because its network service failed in some Chrome/Edge installations.

1. Set GROQ_API_KEY and GROQ_WHISPER_MODEL=whisper-large-v3-turbo in .env.
2. Start Flask with `python app.py` and open http://127.0.0.1:5000/#chat.
3. Allow microphone access. Click microphone to start recording, speak, click again to stop.
4. Wait for transcription; recognized words appear in the editable chat message box. Click Send to ask the AI.

Speech appears after you stop recording, not continuously as you speak. Transcription requires a working Groq connection. Audio is processed in memory and not saved to disk. Never commit .env.
