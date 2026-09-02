export function CompareSnapshotsJSON(from, to, refresh) {
  return window.go.app.App.CompareSnapshotsJSON(from, to, refresh);
}
export function GetVMStatusWails() {
  return window.go.app.App.GetVMStatusWails();
}
export function BuildFileTreeWails(json) {
  return window.go.app.App.BuildFileTreeWails(json);
}
export function BuildRegistryTreeWails(json) {
  return window.go.app.App.BuildRegistryTreeWails(json);
}
export function ReadSnapshotFileWails(snap, path) {
  return window.go.app.App.ReadSnapshotFileWails(snap, path);
}
export function LoadDiffFile(path) {
  return window.go.app.App.LoadDiffFile(path);
}
export function ListSnapshotsWails() {
  return window.go.app.App.ListSnapshotsWails();
}
export function TakeSnapshotWails(name, description, force) {
  return window.go.app.App.TakeSnapshotWails(name, description, force);
}
export function PreserveEvidenceWails(label) {
  return window.go.app.App.PreserveEvidenceWails(label);
}
export function ResetToSnapshotWails(name, clean) {
  return window.go.app.App.ResetToSnapshotWails(name, clean);
}
export function LaunchSnapshotWails(name, clean) {
  return window.go.app.App.LaunchSnapshotWails(name, clean);
}
export function DeleteSnapshotWails(name, force) {
  return window.go.app.App.DeleteSnapshotWails(name, force);
}
export function GetAppLogWails() {
  return window.go.app.App.GetAppLogWails();
}
export function ClearAppLogWails() {
  return window.go.app.App.ClearAppLogWails();
}
export function ListLogFilesWails() {
  return window.go.app.App.ListLogFilesWails();
}
export function TailLogFileWails(path, maxLines) {
  return window.go.app.App.TailLogFileWails(path, maxLines);
}
