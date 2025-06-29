--[[

        Scripted and Published by draxfm.
        repo: github.com/DraxFM/Roblox/WhiteRoom/DanceSpoofer.lua
        Although this project is open source I'd appreciate credits if you are using parts or logic of this script for your own scripts.
        Thank you for using!

--]]


if game.PlaceId ~= 13278749064 then
    game:GetService("StarterGui"):SetCore("SendNotification",{
	Title = "Game unsupported!",
	Text = "You are not in White Room!",
    Duration = 8,
    })
    return
end

local Rayfield = loadstring(game:HttpGet('https://sirius.menu/rayfield'))()
local version = "1.0.0"
local lplr = game:GetService("Players").LocalPlayer

local function bypassDanceGUI(v)
    ui = lplr.PlayerGui:WaitForChild("sg"):WaitForChild("anims")
    ui.Visible = v
    task.spawn(function()
        local vclone = game.ReplicatedStorage.UIClick:Clone()
        vclone.Parent = workspace
        vclone:Play()
        vclone.Ended:Wait()
        vclone:Destroy()
    end)
end

local function bypassServerGUI(v)
    ui = lplr.PlayerGui:WaitForChild("sg"):WaitForChild("servers")
    ui.Visible = v
    task.spawn(function()
        local vclone = game.ReplicatedStorage.UIClick:Clone()
        vclone.Parent = workspace
        vclone:Play()
        vclone.Ended:Wait()
        vclone:Destroy()
    end)
end

local function misc_changeHumanoidStats(v, stat)
    local char = lplr.Character or lplr.CharacterAdded:Wait()
    local hum = char:FindFirstChild("Humanoid")
    if stat == "speed" then
        hum.WalkSpeed = v
    elseif stat == "jpower" then
        hum.JumpPower = v
    end
end

-- Dance Anim Speed Spoofer

local spooferWarningDebounce = false
local function warnSpooferNotLoaded()
    if spooferWarningDebounce then return end
    spooferWarningDebounce = true
    Rayfield:Notify({
    Title = "Animation Spoofer by draxfm",
    Content = "Load the Animation Spoofer first to use this feature!",
    Duration = 7,
    Image = "shield-alert",
    })
    task.wait(7)
    spooferWarningDebounce = false
end

local spooferLoaded = false
local v_u1 = nil
local v_u2 = nil
local v_u3 = nil
local danceUIPath = lplr.PlayerGui.sg.anims
v_u_selected = nil
local function v_u4(arg1, arg2)
    if not spooferLoaded then return end
	if lplr.Character:FindFirstChild("UiepAnim") then
		if v_u3 then
			v_u3.BackgroundColor3 = Color3.fromRGB(231, 231, 231)
		end
		v_u1:AdjustSpeed(arg1)
		arg2.BackgroundColor3 = Color3.fromRGB(61, 129, 255)
		v_u3 = arg2
	end
end

local function v_u5(arg1, arg2)
    if not spooferLoaded then return end
	if v_u1 ~= nil then
		v_u1:Stop()
	end
	if v_u2 then
		v_u2.BackgroundColor3 = Color3.fromRGB(248, 248, 248)
        if v_u_selected ~= nil then v_u_selected.Visible = false end
	end
	if v_u3 then
		v_u3.BackgroundColor3 = Color3.fromRGB(231, 231, 231)
	end
	local v_uiepanim = lplr.Character:FindFirstChild("UiepAnim")
	local v1 = "rbxassetid://" .. arg1
	if v_uiepanim then
		if v_uiepanim.AnimationId == v1 then
			v_uiepanim:Destroy()
			return
		end
		v_uiepanim:Destroy()
	end
	local v_animation = Instance.new("Animation")
	v_animation.Name = "UiepAnim"
	v_animation.AnimationId = v1
	v_animation.Parent = lplr.Character
	v_u1 = lplr.Character.Humanoid:LoadAnimation(v_animation)
	v_u1:Play()
	if v_u_selected ~= nil then
        v_u_selected.Visible = true
        v_u_selected.Parent = arg2
    end
	arg2.BackgroundColor3 = Color3.fromRGB(220, 220, 220)
	v_u2 = arg2
end

local function loadAnimSpoofer()
    if spooferLoaded then return end
    spooferLoaded = true
    danceUIPath.LocalScript.Disabled = true

    for _, v_u6 in pairs(danceUIPath.Frame.ScrollingFrame:GetDescendants()) do
        if v_u6.Name == "Selected" then
            v_u6.Visible = false
            v_u6.Parent = danceUIPath.Frame
            v_u_selected = v_u6
        end
        if v_u6:IsA("TextButton") then
            v_u6.BackgroundColor3 = Color3.fromRGB(248, 248, 248)
            v_u6.MouseButton1Click:Connect(function()
                v_u5(v_u6.Name, v_u6)
            end)
        end
    end
    if danceUIPath.Frame:FindFirstChild("Selected") then
        v_u_selected = danceUIPath.Frame.Selected
    end
    if lplr.Character:FindFirstChild("UiepAnim") then
        for i,v in pairs(lplr.Character.Humanoid:GetPlayingAnimationTracks()) do
            if v.Name == "UiepAnim" then
	            v:Stop()
            end
        end
        lplr.Character:FindFirstChild("UiepAnim"):Destroy()
    end
    danceUIPath.Frame.SpeedPicker.Slow.MouseButton1Click:Connect(function()
        v_u4(0.5, danceUIPath.Frame.SpeedPicker.Slow)
    end)
    danceUIPath.Frame.SpeedPicker.Default.MouseButton1Click:Connect(function()
        v_u4(1, danceUIPath.Frame.SpeedPicker.Default)
    end)
    danceUIPath.Frame.SpeedPicker.Fast.MouseButton1Click:Connect(function()
        v_u4(2, danceUIPath.Frame.SpeedPicker.Fast)
    end)
    Rayfield:Notify({
    Title = "Animation Spoofer by draxfm",
    Content = "Animation Spoofer loaded.",
    Duration = 7,
    Image = "info",
    })
end

local Window = Rayfield:CreateWindow({ -- dont judge me i copied this part from the rayfield docs lol
   Name = "White Room Dance Spoofer by draxfm v"..version,
   Icon = 0, -- Icon in Topbar. Can use Lucide Icons (string) or Roblox Image (number). 0 to use no icon (default).
   LoadingTitle = "White Room Dance Spoofer | Loading Interface",
   LoadingSubtitle = "by draxfm",
   ShowText = "White Room Dance Spoofer",
   Theme = "Default", -- Check https://docs.sirius.menu/rayfield/configuration/themes

   ToggleUIKeybind = "H",

   DisableRayfieldPrompts = false,
   DisableBuildWarnings = false,

   ConfigurationSaving = {
      Enabled = false,
      FolderName = nil,
      FileName = "WRDS"
   },

   Discord = {
      Enabled = true, -- Prompt the user to join your Discord server if their executor supports it
      Invite = "sEXECdC3Et", -- The Discord invite code, do not include discord.gg/. E.g. discord.gg/ ABCD would be ABCD
      RememberJoins = true -- Set this to false to make them join the discord every time they load it up
   },

   KeySystem = false, -- Set this to true to use our key system
   KeySettings = {
      Title = "Untitled",
      Subtitle = "Key System",
      Note = "No method of obtaining the key is provided", -- Use this to tell the user how to get a key
      FileName = "Key", -- It is recommended to use something unique as other scripts using Rayfield may overwrite your key file
      SaveKey = true, -- The user's key will be saved, but if you change the key, they will be unable to use your script
      GrabKeyFromSite = false, -- If this is true, set Key below to the RAW site you would like Rayfield to get the key from
      Key = {"Hello"} -- List of keys that will be accepted by the system, can be RAW file links (pastebin, github etc) or simple strings ("hello","key22")
   }
})

local Misc = Window:CreateTab("Miscellanous")
local Other = Window:CreateTab("Other Scripts")
local Credits = Window:CreateTab("Credits")

local misc_dance_sec = Misc:CreateSection("Dance Mods")

local misc_danceUI_toggle = Misc:CreateToggle({
   Name = "Toggle Dance Menu (Bypasses Group Join Requirement)",
   CurrentValue = false,
   Flag = "Toggle1",
   Callback = function(v)
   bypassDanceGUI(v)
   end,
})

local misc_loadSpoofer_button = Misc:CreateButton({
   Name = "Load Dance Animation Spoofer",
   Callback = function()
   loadAnimSpoofer()
   end,
})

local misc_speedSpoof_slider = Misc:CreateSlider({
   Name = "Spoof Dance Speed",
   Range = {0.1, 10},
   Increment = 0.1,
   CurrentValue = 1,
   Flag = "Slider1",
   Callback = function(v)
    if not spooferLoaded then
        warnSpooferNotLoaded()
        return
    end
    v_u4(v, danceUIPath.Frame.SpeedPicker.Default)
    end,
})

local misc_more_sec = Misc:CreateSection("Miscellanous")

local misc_bypserverui_toggle = Misc:CreateToggle({
   Name = "Toggle Beta Server UI",
   CurrentValue = false,
   Flag = "Toggle1",
   Callback = function(v)
   bypassServerGUI(v)
   end,
})

local misc_player_sec = Misc:CreateSection("Player")

local misc_ws_slider = Misc:CreateSlider({
   Name = "WalkSpeed",
   Range = {8, 50},
   Increment = 1,
   CurrentValue = 16,
   Flag = "Slider1",
   Callback = function(v)
   misc_changeHumanoidStats(v, "speed")
   end,
})

local misc_jp_slider = Misc:CreateSlider({
   Name = "JumpPower",
   Range = {25, 200},
   Increment = 5,
   CurrentValue = 50,
   Flag = "Slider1",
   Callback = function(v)
   misc_changeHumanoidStats(v, "jpower")
   end,
})

local otherSec = Other:CreateSection("Third Party Scripts")
local otherSecWarning = Other:CreateLabel("These scripts are not under my control. Use at your own risk!", "shield-alert")

local other_iy_button = Other:CreateButton({
   Name = "Infinite Yield",
   Callback = function()
   loadstring(game:HttpGet("https://raw.githubusercontent.com/EdgeIY/infiniteyield/master/source"))()
   end,
})

local other_bb_button = Other:CreateButton({
   Name = "BetterBypasser",
   Callback = function()
   loadstring(game:HttpGet("https://github.com/Synergy-Networks/products/raw/main/BetterBypasser/loader.lua"))()
   end,
})

local creditsText = Credits:CreateParagraph({Title = "Credits", Content = "Scripter: draxfm\nOther Tabs: Credits go to their respective authors\nUI Library: Rayfield\nDiscord: draxfm\nDiscord Server: discord.gg/sEXECdC3Et\n\nAnd all thanks to you for using this script. I don't make any money doing this, you can simply support me by sharing the script to others!"})

local other_iy_button = Credits:CreateButton({
   Name = "Copy Discord Invite Link",
   Callback = function()
   setclipboard("https://discord.gg/sEXECdC3Et")
    Rayfield:Notify({
    Title = "White Room Essentials",
    Content = "Discord Invite link copied.",
    Duration = 4,
    Image = "info",
    })
   end,
})
