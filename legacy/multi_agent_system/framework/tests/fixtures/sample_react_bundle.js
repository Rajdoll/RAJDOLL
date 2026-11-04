const router = createBrowserRouter([
  {path: '/dashboard', element: Dashboard},
  {path: '/settings', element: Settings},
  {path: '/users/:id', element: UserProfile}
]);
