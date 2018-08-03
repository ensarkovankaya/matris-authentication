#!/usr/bin/env bash
set -e

install () {
    # Install Dependencies
    if [ "$NODE_ENV" == "prod" ] || [ "$NODE_ENV" == "production" ]; then
        npm install --only=prod
    else
        npm install
    fi
}

if [ "$1" == "bash" ]; then
    /usr/bin/env bash
elif [ "$1" == "test" ]; then
    npm run test
elif [ "$1" == "install" ]; then
    install
elif [ "$1" == "e2e" ]; then
    npm run e2e
else
    # If environment development use nodemon to watch file changes
    # Otherwise just run the server
    if [ "$NODE_ENV" == "development" ] || [ "$NODE_ENV" == "dev" ]; then
        npm run watch
    else
        # Install dependencies if node_modules not exists
        if [ ! -d "node_modules" ]; then
            install
        fi
        npm run start
    fi
fi