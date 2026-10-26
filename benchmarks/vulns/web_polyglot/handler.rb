get "/clone" do
  system("git clone #{params[:repo]}")
end
data = Marshal.load(params[:payload])
