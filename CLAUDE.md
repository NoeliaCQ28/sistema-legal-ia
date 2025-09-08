# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LegalIA is a Streamlit-based legal case management system that integrates with PostgreSQL database, Supabase storage, and Google Gemini AI. The application provides a web interface for managing legal cases, clients, lawyers, and document storage.

## Development Environment

### Dependencies
Install dependencies using:
```bash
pip install -r requirements.txt
```

Required packages:
- `streamlit` - Web framework
- `pandas` - Data manipulation
- `psycopg2-binary` - PostgreSQL adapter
- `google-generativeai` - Google Gemini AI integration
- `supabase` - Supabase client for file storage

System dependencies (for deployment):
- `libpq-dev` - PostgreSQL development headers

### Running the Application
```bash
streamlit run app.py
```

## Architecture

### Core Structure
The application follows a single-file architecture (`app.py`) with clear separation of concerns:

- **Configuration & Connections** (lines 8-48): Page config, database connection, Supabase client, and AI model setup
- **Backend Functions** (lines 50-91): Database operations, stored procedure calls, and data retrieval
- **Frontend Interface** (lines 92-297): Streamlit UI with modular pages

### Database Integration
- Uses PostgreSQL with stored procedures for data operations
- Connection caching via `@st.cache_resource` decorator
- Stored procedures called: `crear_caso`, `actualizar_estado_caso`, `crear_cliente`, `crear_abogado`, `crear_documento`
- Custom function: `obtener_casos_detallados()` for detailed case views

### External Services
- **Supabase**: Document storage in `documentos_casos` bucket
- **Google Gemini AI**: Case summary generation using `gemini-1.5-flash` model
- **PostgreSQL**: Primary data storage

### Key Features
1. **Dashboard**: Case visualization with AI-powered summaries and status updates
2. **Case Creation**: New case registration with client and lawyer assignment  
3. **Document Management**: File upload to Supabase with metadata tracking
4. **User Management**: Client and lawyer registration and listing

### Configuration Requirements
The application requires Streamlit secrets configuration for:
- `database`: PostgreSQL connection parameters (host, port, dbname, user, password)
- `supabase`: URL and service key
- `ai`: Google API key for Gemini model

### Error Handling Patterns
- Database connection failures are gracefully handled with user feedback
- File upload conflicts are detected and reported
- AI service unavailability is handled with warnings rather than errors
- All database operations use try-catch with rollback on failures

## Development Notes

- The application uses Spanish language for UI elements
- File storage paths follow pattern: `{case_id}/{filename}`
- Document downloads use signed URLs with 60-second expiration
- Status updates trigger automatic page rerun for immediate feedback