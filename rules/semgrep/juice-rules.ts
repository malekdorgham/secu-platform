class SearchResultComponent {
  filterTable (queryParam: string) {
    // ruleid: juice-angular-bypass-sanitizer
    this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
  }
  track (results: any) {
    // ruleid: juice-angular-bypass-sanitizer
    this.orderNo = this.sanitizer.bypassSecurityTrustHtml(`<code>${results.data[0].orderId}</code>`)
  }
  safe () {
    // ok: juice-angular-bypass-sanitizer
    this.icon = this.sanitizer.bypassSecurityTrustHtml('<b>static</b>')
  }
}
// ruleid: juice-directory-listing
app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true }))
// ok: juice-directory-listing
app.use('/public', express.static('public'))
function b2b (orderLinesData: string) {
  const sandbox = { safeEval, orderLinesData }
  // ruleid: juice-node-vm-sandbox
  vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
}
function safeParse (data: string) {
  // ok: juice-node-vm-sandbox
  return JSON.parse(data)
}
function update (req: any) {
  // ruleid: juice-nosql-update-selector
  db.reviewsCollection.update(
    { _id: req.body.id },
    { $set: { message: req.body.message } },
    { multi: true }
  )
}
function safeUpdate (req: any) {
  const id = String(req.body.id)
  // ok: juice-nosql-update-selector
  db.reviewsCollection.update({ _id: id }, { $set: { message: 'x' } })
}
function reviews (req: any) {
  const id = req.params.id
  // ruleid: juice-nosql-where-injection
  db.reviewsCollection.find({ $where: 'this.product == ' + id })
}
function safeOrders () {
  // ok: juice-nosql-where-injection
  db.ordersCollection.find({ $where: 'this.total > 10' })
}
export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    // ruleid: juice-open-redirect-includes
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}
export const safeRedirect = (url: string) => {
  // ok: juice-open-redirect-includes
  return redirectAllowlist.includes(new URL(url).origin)
}
function login (req: any) {
  // ruleid: juice-sequelize-raw-sqli
  models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}'`, { plain: true })
}
function search (req: any) {
  let criteria: any = req.query.q ?? ''
  criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
  // ruleid: juice-sequelize-raw-sqli
  models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`)
}
function safeNumber (req: any) {
  const id = Number(req.params.id)
  // ok: juice-sequelize-raw-sqli
  models.sequelize.query(`SELECT * FROM Products WHERE id = ${id}`)
}
