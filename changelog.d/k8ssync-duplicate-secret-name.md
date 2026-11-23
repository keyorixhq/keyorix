### Security
- **The Kubernetes sync fetcher refuses a secret list that names one secret twice.**
  The server keeps secret names unique within a project environment, so a list that repeats a
  name, on one page or across pages, is not an honest answer (a hostile or broken server). The
  fetcher used to take the first listed id and stop; it now reads the whole list and fails the
  lookup if the name appears more than once, without treating that as a removed secret. Because
  a match no longer ends the walk, the number of list pages it will read per environment is
  bounded (1000 pages of 100), where before only a missing secret walked to the last page the
  server claimed.
