#!/bin/bash

# Correr IdP
cd idp
py app.py

# Correr web
cd ../service
py app.py
