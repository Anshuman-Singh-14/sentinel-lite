import { useCallback, useEffect, useState } from "react";
import { api } from "./api.js";

// Loads a list from the API and gives back a function to reload it after a change.
//   const users = useList("/api/admin/users");
//   users.items / users.error / users.reload()
export function useList(path) {
  const [items, setItems] = useState([]);
  const [error, setError] = useState("");
  const reload = useCallback(() => {
    api(path)
      .then((data) => {
        setItems(data);
        setError("");
      })
      .catch((err) => setError(err.message));
  }, [path]);
  useEffect(reload, [reload]);
  return { items, error, setError, reload };
}
