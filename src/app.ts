import 'reflect-metadata'

import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import http from 'http'
import morgan from 'morgan'

import { createLogger } from '@/helpers'
import { router } from '@/router'

export const logger = createLogger()

// Global configs
//
dotenv.config()

const MAX_SHUTDOWN_WAIT_TIME = 5000 // ms
const PORT = Number(process.env.PORT) || 3000
const HOST = process.env.HOST || 'localhost'
const URL = `http://${HOST}:${PORT}`

// App setup
//
const app = express()
const server = http.createServer(app)

app.use(
    morgan(':method :url :status :res[content-length] - :response-time ms', {
        stream: {
            write: message => logger.info(message.trim()),
        },
    }),
)

app.use(cors())
app.use(express.json({ limit: '50mb' }))
app.use(router)

const handleShutDown = (signal: NodeJS.Signals) => {
    logger.info(`Received ${signal}. Shutting down gracefully...`)

    server.close(err => {
        if (err) {
            logger.error('Failed to close server')
            return
        }

        logger.info('Server process terminated')
        process.exit(0)
    })

    // Force close server after n seconds
    setTimeout(() => {
        logger.warning('Forcing server shutdown')

        process.exit(1)
    }, MAX_SHUTDOWN_WAIT_TIME)
}

// Start the server
//
server.listen(PORT, HOST, () => logger.info(`Custom detector service started on ${URL}`))

// Listen for termination signals
process.on('SIGINT', handleShutDown)
process.on('SIGTERM', handleShutDown)

// Exports
//
export { app, server }
