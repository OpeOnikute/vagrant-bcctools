const express = require('express')
const fs = require("fs")
const path = require("path")

const console = require('console')
const levenshtein = require('fast-levenshtein')

const { mainHandler } = require("./handler");

//Tweak this to change how easily spotted the long operation is going to be.
//When set to 100 it should be the only visible operation
const HOW_OBVIOUS_THE_FLAME_GRAPH_SHOULD_BE_ON_SCALE_1_TO_100 = 80

const someFakeModule = (function someFakeModule () {
  return {
    calculateStringDistance (a, b) {
      //Here's where heavy sunchronous computation happens
      return levenshtein.get(a, b, {
        useCollator: true
      })
    }
  }
})()


const app = express()

app.get('/', mainHandler)

app.get('/api/tick', (req, res) => {
  Promise.resolve('asynchronous flow will make our stacktrace more realistic'.repeat(HOW_OBVIOUS_THE_FLAME_GRAPH_SHOULD_BE_ON_SCALE_1_TO_100))
        .then(text => {
          const randomText = Math.random().toString(32).repeat(HOW_OBVIOUS_THE_FLAME_GRAPH_SHOULD_BE_ON_SCALE_1_TO_100)
          return someFakeModule.calculateStringDistance(text, randomText)
        })
        .then(result => res.end(`result: ${result}`))
})

app.get('/api/end', () => process.exit())

const port = process.env.PORT || 8080;

app.listen(port, () => {
  if (!process.env.SILENT_START) {
    console.log(`go to http://localhost:${port}/ to generate traffic`);
  }
})