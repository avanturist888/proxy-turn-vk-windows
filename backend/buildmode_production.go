//go:build production

package backend

// handOffEnabled — передача запуска задаче планировщика/UAC только в
// собранном приложении: `wails build` запускает исполняемый файл и для
// генерации привязок (тег bindings), а `wails dev` — для разработки.
const handOffEnabled = true
