# ThreatWeave – Graph & Backend Module

## Overview

ThreatWeave is an AI-powered Cyber Threat Intelligence platform that integrates multiple OSINT sources into a Neo4j Knowledge Graph and provides AI-powered threat reasoning through FastAPI.

This backend module was developed by **Member 2 (Graph & Backend Engineer)**.

---

# Features

- Neo4j Knowledge Graph
- Threat Actor Management
- Malware Relationships
- MITRE ATT&CK Techniques
- CVE Integration
- IOC Integration
- OTX Pulse Integration
- AI Question Answering (Groq + LangGraph)
- Hidden Link Detection
- Relationship Scoring
- Graph Visualization API
- Dashboard Analytics API
- FastAPI Backend
- Swagger Documentation

---

# Project Structure

```
DarkWebProject
│
├── ai/
│   ├── graph_reasoner.py
│   ├── hidden_links.py
│   ├── scoring.py
│   ├── langgraph_agent.py
│   └── prompts.py
│
├── api/
│   └── app.py
│
├── graph/
│   ├── connection.py
│   └── load_actors.py
│
├── queries/
│   ├── analytics_queries.py
│   ├── search_queries.py
│   └── visualization_queries.py
│
├── utils/
│   └── entity_extractor.py
│
├── datasets/
│
├── .env.example
├── requirements.txt
└── README.md
```

---

# Requirements

- Python 3.11+
- Neo4j Desktop
- Groq API Key

---

# Installation

## Clone the project

```bash
git clone <repository_url>
cd DarkWebProject
```

---

## Create Virtual Environment

Windows

```bash
python -m venv venv_windows
```

Activate

```bash
venv_windows\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Environment Variables

Create a file named `.env`

Example:

```env
GROQ_API_KEY=your_groq_api_key

NEO4J_URI=neo4j://127.0.0.1:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_password
```

---

# Start Neo4j

Open Neo4j Desktop

Start the ThreatWeave database.

---

# Run Backend

From the project root

```bash
python -m uvicorn api.app:app --reload
```

Server

```
http://127.0.0.1:8000
```

Swagger

```
http://127.0.0.1:8000/docs
```

---

# Available APIs

## Core APIs

```
GET /
GET /actors
GET /malware
GET /graph
GET /graph-data
GET /visualization
```

---

## AI APIs

```
GET /ask
GET /hidden-links
GET /scores
```

---

## Search APIs

```
GET /actor/{name}
GET /malware/{name}
GET /technique/{technique_id}
GET /cve/{cve_id}
GET /ioc/{value}
GET /pulse/{name}
```

---

## Analytics APIs

```
GET /dashboard
GET /statistics
GET /graph-summary
GET /relationship-summary
GET /top-threat-actors
GET /top-malware
GET /top-techniques
```

---

# Technologies Used

- Python
- FastAPI
- Neo4j
- Cypher
- LangGraph
- LangChain
- Groq LLM
- Pandas
- dotenv

---

# Dataset

The Knowledge Graph is built using:

- MITRE ATT&CK Groups
- MITRE Malware
- MITRE Techniques
- CVE Dataset
- AlienVault OTX Pulses
- IOC Dataset

---

# AI Capabilities

- Cyber Threat Question Answering
- Threat Actor Identification
- Malware Discovery
- Hidden Link Detection
- Relationship Scoring
- Knowledge Graph Reasoning

---

# Graph Relationships

```
ThreatActor ---- USES ---- Malware

IOC ----------- INDICATES ---- Malware

Pulse --------- MENTIONS ---- ThreatActor
```

---

# Visualization

The backend provides graph visualization data through

```
GET /visualization
```

which returns

```json
{
    "nodes": [],
    "edges": []
}
```

This endpoint is intended for frontend visualization libraries such as Cytoscape.js, D3.js, or React Flow.

---

# Notes for Member 3

1. Install all dependencies.

2. Create the `.env` file.

3. Start Neo4j.

4. Run FastAPI.

5. Open Swagger.

6. Use the provided APIs for frontend integration.

No backend modifications are required unless adding new features.

---

# Developed By

ThreatWeave Project

Member 2 – Graph & Backend Engineer

PES University