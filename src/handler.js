const fs = require("fs")
const path = require("path")
module.exports = {
    mainHandler: function (req, res) {
        Promise.resolve('asynchronous flow will make our stacktrace more realistic'.repeat(100))
        .then(() => {
            fs.open(path.join(__dirname, "text.txt"), function(err,data){
                if (err) {
                    console.log(err);
                    return;
                }
                return console.log("gotten file")
              });
        }).then(() => {
            return res.send(`
            <h2>Take a look at the network tab in devtools.</h2>
            <p><strong>Node Version:</strong>${process.env.NODE_VERSION}</p>
            <script>
                function loops(func) {
                  return func().then(_ => setTimeout(loops, 20, func))
                }
                loops(_ => fetch('api/tick'))
            </script>
            `)
        });
    }
}