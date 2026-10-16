-- author: draxfm and also gemini yo creds
-- anyways if you use logic or skid from this script (wont stop ya) please credit me so me and marlon can slay foids

if getgenv().draxfm_saktkia51 ~= nil then return end
getgenv().draxfm_saktkia51 = true

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local Workspace = game:GetService("Workspace")
local UserInputService = game:GetService("UserInputService")
local TweenService = game:GetService("TweenService")
local HttpService = game:GetService("HttpService")
local CoreGui = game:GetService("CoreGui")
local LocalPlayer = Players.LocalPlayer
local Camera = Workspace.CurrentCamera

local KillersFolder = Workspace:WaitForChild("Killers", 5)
local CharactersToKillFolder = Workspace:WaitForChild("Characters to kill", 5)

local scriptname = "saktkia51 cuz y not"

local activeConnections = {}
local function trackConnection(conn)
    table.insert(activeConnections, conn)
    return conn
end

getgenv().SilentAimConfig = getgenv().SilentAimConfig or {
    Enabled = false,
    FOV = 150,
    WallCheck = false,
    Wallbang = true,
    TargetPart = "HumanoidRootPart",
    TargetTypes = {
        Killers = true,
        Players = false,
    },
    Prediction = true,
    PredictionFactor = 1.0,
    ShowFOV = true,
    FOVColor = Color3.fromRGB(0, 229, 255),
    FOVThickness = 1,
}

getgenv().ESPConfig = getgenv().ESPConfig or {
    Enabled = true,
    Box = true,
    Tracer = true,
    Skeleton = true,
    HealthBar = true,
    Name = true,
    Distance = true,
    KillerColor = Color3.fromRGB(255, 50, 50),
    PlayerColor = Color3.fromRGB(50, 255, 255),
    TracerOrigin = "Bottom",
}

getgenv().OPConfig = getgenv().OPConfig or {
    InstantHit = true,
    NoCooldown = true,
    InfiniteAmmo = true,
    NoRecoil = true,
    Autofire = true,
    HitboxExpander = {
        Enabled = false,
        Size = 10,
        Transparency = 0.85,
        TargetPart = "HumanoidRootPart"
    }
}

local BlacklistedNames = {
    ["Jane"] = true,
    ["Giant"] = true
}

local function reqDcJoin()
    if request then
        local payload = HttpService:JSONEncode({cmd = "INVITE_BROWSER", args = {code = "sEXECdC3Et"}, nonce = HttpService:GenerateGUID(false)})
        pcall(function() request({Url = "http://127.0.0.1:6463/rpc?v=1", Method = "POST", Headers = {["Content-Type"] = "application/json", ["Origin"] = "https://discord.com"}, Body = payload}) end)
    end
end

local hideKeybind = Enum.KeyCode.RightShift

local NotificationGui = Instance.new("ScreenGui")
NotificationGui.Name = "OPNotificationGui"
NotificationGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
pcall(function() NotificationGui.Parent = CoreGui end)
if not NotificationGui.Parent then NotificationGui.Parent = LocalPlayer:WaitForChild("PlayerGui") end

local NotifContainer = Instance.new("Frame")
NotifContainer.Name = "Container"
NotifContainer.Size = UDim2.new(0, 300, 1, -40)
NotifContainer.Position = UDim2.new(1, -320, 0, 20)
NotifContainer.BackgroundTransparency = 1
NotifContainer.Parent = NotificationGui

local NotifLayout = Instance.new("UIListLayout")
NotifLayout.SortOrder = Enum.SortOrder.LayoutOrder
NotifLayout.VerticalAlignment = Enum.VerticalAlignment.Bottom
NotifLayout.Padding = UDim.new(0, 10)
NotifLayout.Parent = NotifContainer

local function Notify(title, content, duration)
    duration = duration or 3
    
    local card = Instance.new("Frame")
    card.Size = UDim2.new(1, 0, 0, 70)
    card.BackgroundColor3 = Color3.fromRGB(20, 20, 28)
    card.BorderSizePixel = 0
    card.BackgroundTransparency = 1
    card.Position = UDim2.new(1, 50, 0, 0)
    
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 8)
    corner.Parent = card
    
    local stroke = Instance.new("UIStroke")
    stroke.Color = Color3.fromRGB(0, 229, 255)
    stroke.Transparency = 1
    stroke.Parent = card
    
    local titleLbl = Instance.new("TextLabel")
    titleLbl.Size = UDim2.new(1, -20, 0, 24)
    titleLbl.Position = UDim2.new(0, 12, 0, 8)
    titleLbl.BackgroundTransparency = 1
    titleLbl.Font = Enum.Font.GothamBold
    titleLbl.Text = title
    titleLbl.TextColor3 = Color3.fromRGB(255, 255, 255)
    titleLbl.TextSize = 14
    titleLbl.TextXAlignment = Enum.TextXAlignment.Left
    titleLbl.TextTransparency = 1
    titleLbl.Parent = card
    
    local descLbl = Instance.new("TextLabel")
    descLbl.Size = UDim2.new(1, -20, 0, 30)
    descLbl.Position = UDim2.new(0, 12, 0, 32)
    descLbl.BackgroundTransparency = 1
    descLbl.Font = Enum.Font.Gotham
    descLbl.Text = content
    descLbl.TextColor3 = Color3.fromRGB(170, 170, 190)
    descLbl.TextSize = 12
    descLbl.TextWrapped = true
    descLbl.TextXAlignment = Enum.TextXAlignment.Left
    descLbl.TextTransparency = 1
    descLbl.Parent = card
    
    card.Parent = NotifContainer
    
    TweenService:Create(card, TweenInfo.new(0.3, Enum.EasingStyle.Quart, Enum.EasingDirection.Out), {BackgroundTransparency = 0.1, Position = UDim2.new(0, 0, 0, 0)}):Play()
    TweenService:Create(stroke, TweenInfo.new(0.3), {Transparency = 0.5}):Play()
    TweenService:Create(titleLbl, TweenInfo.new(0.3), {TextTransparency = 0}):Play()
    TweenService:Create(descLbl, TweenInfo.new(0.3), {TextTransparency = 0}):Play()
    
    task.delay(duration, function()
        if card and card.Parent then
            local tw = TweenService:Create(card, TweenInfo.new(0.3, Enum.EasingStyle.Quart, Enum.EasingDirection.In), {BackgroundTransparency = 1, Position = UDim2.new(1, 50, 0, 0)})
            TweenService:Create(stroke, TweenInfo.new(0.3), {Transparency = 1}):Play()
            TweenService:Create(titleLbl, TweenInfo.new(0.3), {TextTransparency = 1}):Play()
            TweenService:Create(descLbl, TweenInfo.new(0.3), {TextTransparency = 1}):Play()
            tw:Play()
            tw.Completed:Connect(function() card:Destroy() end)
        end
    end)
end

local ScreenGui
local Library = {}
function Library:CreateWindow(config)
    local WindowName = config.Name or "Area 51 Pro Suite" -- fym area 51 pro suite holy vibecode
    
    ScreenGui = Instance.new("ScreenGui")
    ScreenGui.Name = "OPSuiteGUI"
    pcall(function() ScreenGui.Parent = CoreGui end)
    if not ScreenGui.Parent then ScreenGui.Parent = LocalPlayer:WaitForChild("PlayerGui") end
    
    local MainFrame = Instance.new("Frame")
    MainFrame.Name = "MainFrame"
    MainFrame.Size = UDim2.new(0, 620, 0, 420)
    MainFrame.Position = UDim2.new(0.5, -310, 0.5, -210)
    MainFrame.BackgroundColor3 = Color3.fromRGB(15, 15, 22)
    MainFrame.BorderSizePixel = 0
    MainFrame.Parent = ScreenGui
    
    local MainCorner = Instance.new("UICorner")
    MainCorner.CornerRadius = UDim.new(0, 10)
    MainCorner.Parent = MainFrame
    
    local MainStroke = Instance.new("UIStroke")
    MainStroke.Color = Color3.fromRGB(45, 45, 65)
    MainStroke.Thickness = 1.5
    MainStroke.Parent = MainFrame
    
    local TopBar = Instance.new("Frame")
    TopBar.Name = "TopBar"
    TopBar.Size = UDim2.new(1, 0, 0, 40)
    TopBar.BackgroundTransparency = 1
    TopBar.Parent = MainFrame
    
    local Title = Instance.new("TextLabel")
    Title.Size = UDim2.new(0, 300, 1, 0)
    Title.Position = UDim2.new(0, 15, 0, 0)
    Title.BackgroundTransparency = 1
    Title.Font = Enum.Font.GothamBold
    Title.Text = WindowName
    Title.TextColor3 = Color3.fromRGB(255, 255, 255)
    Title.TextSize = 15
    Title.TextXAlignment = Enum.TextXAlignment.Left
    Title.Parent = TopBar
    
    local dragging, dragInput, dragStart, startPos
    trackConnection(TopBar.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging = true
            dragStart = input.Position
            startPos = MainFrame.Position
            trackConnection(input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then
                    dragging = false
                end
            end))
        end
    end))
    trackConnection(TopBar.InputChanged:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseMovement then
            dragInput = input
        end
    end))
    trackConnection(UserInputService.InputChanged:Connect(function(input)
        if input == dragInput and dragging then
            local delta = input.Position - dragStart
            MainFrame.Position = UDim2.new(startPos.X.Scale, startPos.X.Offset + delta.X, startPos.Y.Scale, startPos.Y.Offset + delta.Y)
        end
    end))
    
    local Sidebar = Instance.new("ScrollingFrame")
    Sidebar.Name = "Sidebar"
    Sidebar.Size = UDim2.new(0, 150, 1, -40)
    Sidebar.Position = UDim2.new(0, 0, 0, 40)
    Sidebar.BackgroundTransparency = 1
    Sidebar.BorderSizePixel = 0
    Sidebar.CanvasSize = UDim2.new(0, 0, 0, 0)
    Sidebar.ScrollBarThickness = 0
    Sidebar.Parent = MainFrame
    
    local SidebarLayout = Instance.new("UIListLayout")
    SidebarLayout.SortOrder = Enum.SortOrder.LayoutOrder
    SidebarLayout.Padding = UDim.new(0, 4)
    SidebarLayout.Parent = Sidebar
    
    local SidebarPadding = Instance.new("UIPadding")
    SidebarPadding.PaddingTop = UDim.new(0, 10)
    SidebarPadding.PaddingLeft = UDim.new(0, 10)
    SidebarPadding.PaddingRight = UDim.new(0, 10)
    SidebarPadding.Parent = Sidebar
    
    local ContainerHolder = Instance.new("Frame")
    ContainerHolder.Name = "ContainerHolder"
    ContainerHolder.Size = UDim2.new(1, -160, 1, -50)
    ContainerHolder.Position = UDim2.new(0, 155, 0, 45)
    ContainerHolder.BackgroundTransparency = 1
    ContainerHolder.Parent = MainFrame
    
    local Tabs = {}
    local FirstTab = true
    
    function Library:AddTab(tabName)
        local TabButton = Instance.new("TextButton")
        TabButton.Size = UDim2.new(1, 0, 0, 34)
        TabButton.BackgroundColor3 = Color3.fromRGB(22, 22, 32)
        TabButton.BackgroundTransparency = FirstTab and 0 or 1
        TabButton.BorderSizePixel = 0
        TabButton.Font = Enum.Font.GothamMedium
        TabButton.Text = tabName
        TabButton.TextColor3 = FirstTab and Color3.fromRGB(0, 229, 255) or Color3.fromRGB(150, 150, 170)
        TabButton.TextSize = 13
        TabButton.Parent = Sidebar
        
        local BtnCorner = Instance.new("UICorner")
        BtnCorner.CornerRadius = UDim.new(0, 6)
        BtnCorner.Parent = TabButton
        
        local TabContent = Instance.new("ScrollingFrame")
        TabContent.Name = tabName .. "Content"
        TabContent.Size = UDim2.new(1, 0, 1, 0)
        TabContent.BackgroundTransparency = 1
        TabContent.BorderSizePixel = 0
        TabContent.CanvasSize = UDim2.new(0, 0, 0, 0)
        TabContent.ScrollBarThickness = 3
        TabContent.ScrollBarImageColor3 = Color3.fromRGB(0, 229, 255)
        TabContent.Visible = FirstTab
        TabContent.Parent = ContainerHolder
        
        local ContentLayout = Instance.new("UIListLayout")
        ContentLayout.SortOrder = Enum.SortOrder.LayoutOrder
        ContentLayout.Padding = UDim.new(0, 10)
        ContentLayout.Parent = TabContent
        
        trackConnection(ContentLayout:GetPropertyChangedSignal("AbsoluteContentSize"):Connect(function()
            TabContent.CanvasSize = UDim2.new(0, 0, 0, ContentLayout.AbsoluteContentSize.Y + 20)
        end))
        
        trackConnection(TabButton.MouseButton1Click:Connect(function()
            for _, t in pairs(Tabs) do
                t.Content.Visible = false
                TweenService:Create(t.Button, TweenInfo.new(0.2), {BackgroundTransparency = 1, TextColor3 = Color3.fromRGB(150, 150, 170)}):Play()
            end
            TabContent.Visible = true
            TweenService:Create(TabButton, TweenInfo.new(0.2), {BackgroundTransparency = 0, TextColor3 = Color3.fromRGB(0, 229, 255)}):Play()
        end))
        
        FirstTab = false
        
        local TabAPI = {}
        
        function TabAPI:AddSection(sectionName)
            local SectionFrame = Instance.new("Frame")
            SectionFrame.Size = UDim2.new(1, -10, 0, 30)
            SectionFrame.BackgroundColor3 = Color3.fromRGB(20, 20, 28)
            SectionFrame.BorderSizePixel = 0
            SectionFrame.Parent = TabContent
            
            local SecCorner = Instance.new("UICorner")
            SecCorner.CornerRadius = UDim.new(0, 6)
            SecCorner.Parent = SectionFrame
            
            local SecTitle = Instance.new("TextLabel")
            SecTitle.Size = UDim2.new(1, -15, 0, 30)
            SecTitle.Position = UDim2.new(0, 12, 0, 0)
            SecTitle.BackgroundTransparency = 1
            SecTitle.Font = Enum.Font.GothamBold
            SecTitle.Text = sectionName
            SecTitle.TextColor3 = Color3.fromRGB(255, 255, 255)
            SecTitle.TextSize = 12
            SecTitle.TextXAlignment = Enum.TextXAlignment.Left
            SecTitle.Parent = SectionFrame
            
            local ElementList = Instance.new("UIListLayout")
            ElementList.SortOrder = Enum.SortOrder.LayoutOrder
            ElementList.Padding = UDim.new(0, 8)
            ElementList.Parent = SectionFrame
            
            local SecPadding = Instance.new("UIPadding")
            SecPadding.PaddingTop = UDim.new(0, 35)
            SecPadding.PaddingBottom = UDim.new(0, 10)
            SecPadding.PaddingLeft = UDim.new(0, 10)
            SecPadding.PaddingRight = UDim.new(0, 10)
            SecPadding.Parent = SectionFrame
            
            trackConnection(ElementList:GetPropertyChangedSignal("AbsoluteContentSize"):Connect(function()
                SectionFrame.Size = UDim2.new(1, -10, 0, ElementList.AbsoluteContentSize.Y + 45)
            end))
            
            local SectionAPI = {}
            
            function SectionAPI:AddLabel(config)
                local LabelTextStr = type(config) == "table" and (config.Text or config.Name) or tostring(config)
                
                local LabelFrame = Instance.new("Frame")
                LabelFrame.Size = UDim2.new(1, 0, 0, 24)
                LabelFrame.BackgroundTransparency = 1
                LabelFrame.Parent = SectionFrame
                
                local Label = Instance.new("TextLabel")
                Label.Size = UDim2.new(1, 0, 1, 0)
                Label.BackgroundTransparency = 1
                Label.Font = Enum.Font.Gotham
                Label.Text = LabelTextStr
                Label.TextColor3 = Color3.fromRGB(170, 170, 190)
                Label.TextSize = 12
                Label.TextXAlignment = Enum.TextXAlignment.Left
                Label.TextWrapped = true
                Label.Parent = LabelFrame
                
                local LabelAPI = {}
                function LabelAPI:SetText(newText)
                    Label.Text = newText
                end
                return LabelAPI
            end
            
            function SectionAPI:AddKeybind(config)
                local KeybindName = config.Name or "Keybind"
                local Default = config.Default or Enum.KeyCode.RightShift
                local Callback = config.Callback or function() end
                
                local KeybindBtn = Instance.new("TextButton")
                KeybindBtn.Size = UDim2.new(1, 0, 0, 30)
                KeybindBtn.BackgroundTransparency = 1
                KeybindBtn.Text = ""
                KeybindBtn.Parent = SectionFrame
                
                local Label = Instance.new("TextLabel")
                Label.Size = UDim2.new(1, -90, 1, 0)
                Label.BackgroundTransparency = 1
                Label.Font = Enum.Font.Gotham
                Label.Text = KeybindName
                Label.TextColor3 = Color3.fromRGB(200, 200, 220)
                Label.TextSize = 12
                Label.TextXAlignment = Enum.TextXAlignment.Left
                Label.Parent = KeybindBtn
                
                local Box = Instance.new("TextButton")
                Box.Size = UDim2.new(0, 80, 0, 22)
                Box.Position = UDim2.new(1, -80, 0.5, -11)
                Box.BackgroundColor3 = Color3.fromRGB(35, 35, 50)
                Box.BorderSizePixel = 0
                Box.Font = Enum.Font.GothamMedium
                Box.Text = Default.Name
                Box.TextColor3 = Color3.fromRGB(0, 229, 255)
                Box.TextSize = 11
                Box.Parent = KeybindBtn
                
                local BoxCorner = Instance.new("UICorner")
                BoxCorner.CornerRadius = UDim.new(0, 4)
                BoxCorner.Parent = Box
                
                local boundKey = Default
                local binding = false
                
                trackConnection(Box.MouseButton1Click:Connect(function()
                    if binding then return end
                    binding = true
                    Box.Text = "..."
                    Box.TextColor3 = Color3.fromRGB(255, 255, 100)
                    
                    local keyConn
                    keyConn = trackConnection(UserInputService.InputBegan:Connect(function(input, gp)
                        if input.UserInputType == Enum.UserInputType.Keyboard then
                            boundKey = input.KeyCode
                            Box.Text = boundKey.Name
                            Box.TextColor3 = Color3.fromRGB(0, 229, 255)
                            binding = false
                            keyConn:Disconnect()
                            Callback(boundKey)
                        end
                    end))
                end))
            end

            function SectionAPI:AddToggle(config)
                local ToggleName = config.Name or "Toggle"
                local Default = config.Default or false
                local Callback = config.Callback or function() end
                
                local ToggleBtn = Instance.new("TextButton")
                ToggleBtn.Size = UDim2.new(1, 0, 0, 30)
                ToggleBtn.BackgroundTransparency = 1
                ToggleBtn.Text = ""
                ToggleBtn.Parent = SectionFrame
                
                local Label = Instance.new("TextLabel")
                Label.Size = UDim2.new(1, -40, 1, 0)
                Label.BackgroundTransparency = 1
                Label.Font = Enum.Font.Gotham
                Label.Text = ToggleName
                Label.TextColor3 = Color3.fromRGB(200, 200, 220)
                Label.TextSize = 12
                Label.TextXAlignment = Enum.TextXAlignment.Left
                Label.Parent = ToggleBtn
                
                local Box = Instance.new("Frame")
                Box.Size = UDim2.new(0, 20, 0, 20)
                Box.Position = UDim2.new(1, -20, 0.5, -10)
                Box.BackgroundColor3 = Default and Color3.fromRGB(0, 229, 255) or Color3.fromRGB(35, 35, 50)
                Box.BorderSizePixel = 0
                Box.Parent = ToggleBtn
                
                local BoxCorner = Instance.new("UICorner")
                BoxCorner.CornerRadius = UDim.new(0, 4)
                BoxCorner.Parent = Box
                
                local state = Default
                trackConnection(ToggleBtn.MouseButton1Click:Connect(function()
                    state = not state
                    TweenService:Create(Box, TweenInfo.new(0.2), {BackgroundColor3 = state and Color3.fromRGB(0, 229, 255) or Color3.fromRGB(35, 35, 50)}):Play()
                    Callback(state)
                end))
            end
            
            function SectionAPI:AddSlider(config)
                local SliderName = config.Name or "Slider"
                local Min = config.Min or 0
                local Max = config.Max or 100
                local Default = config.Default or Min
                local Callback = config.Callback or function() end
                
                local SliderFrame = Instance.new("Frame")
                SliderFrame.Size = UDim2.new(1, 0, 0, 45)
                SliderFrame.BackgroundTransparency = 1
                SliderFrame.Parent = SectionFrame
                
                local Label = Instance.new("TextLabel")
                Label.Size = UDim2.new(1, 0, 0, 20)
                Label.BackgroundTransparency = 1
                Label.Font = Enum.Font.Gotham
                Label.Text = SliderName .. ": " .. tostring(Default)
                Label.TextColor3 = Color3.fromRGB(200, 200, 220)
                Label.TextSize = 12
                Label.TextXAlignment = Enum.TextXAlignment.Left
                Label.Parent = SliderFrame
                
                local Bar = Instance.new("Frame")
                Bar.Size = UDim2.new(1, 0, 0, 6)
                Bar.Position = UDim2.new(0, 0, 0, 28)
                Bar.BackgroundColor3 = Color3.fromRGB(35, 35, 50)
                Bar.BorderSizePixel = 0
                Bar.Parent = SliderFrame
                
                local BarCorner = Instance.new("UICorner")
                BarCorner.CornerRadius = UDim.new(0, 3)
                BarCorner.Parent = Bar
                
                local Fill = Instance.new("Frame")
                Fill.Size = UDim2.new((Default - Min) / (Max - Min), 0, 1, 0)
                Fill.BackgroundColor3 = Color3.fromRGB(0, 229, 255)
                Fill.BorderSizePixel = 0
                Fill.Parent = Bar
                
                local FillCorner = Instance.new("UICorner")
                FillCorner.CornerRadius = UDim.new(0, 3)
                FillCorner.Parent = Fill
                
                local draggingSlider = false
                trackConnection(Bar.InputBegan:Connect(function(input)
                    if input.UserInputType == Enum.UserInputType.MouseButton1 then
                        draggingSlider = true
                    end
                end))
                trackConnection(UserInputService.InputEnded:Connect(function(input)
                    if input.UserInputType == Enum.UserInputType.MouseButton1 then
                        draggingSlider = false
                    end
                end))
                trackConnection(UserInputService.InputChanged:Connect(function(input)
                    if draggingSlider and input.UserInputType == Enum.UserInputType.MouseMovement then
                        local pos = math.clamp((input.Position.X - Bar.AbsolutePosition.X) / Bar.AbsoluteSize.X, 0, 1)
                        local val = math.floor(Min + ((Max - Min) * pos))
                        Fill.Size = UDim2.new(pos, 0, 1, 0)
                        Label.Text = SliderName .. ": " .. tostring(val)
                        Callback(val)
                    end
                end))
            end
            
            function SectionAPI:AddDropdown(config)
                local DropName = config.Name or "Dropdown"
                local Options = config.Options or {}
                local Default = config.Default
                local IsMulti = config.Multi or false
                local Callback = config.Callback or function() end
                
                local DropFrame = Instance.new("Frame")
                DropFrame.Size = UDim2.new(1, 0, 0, 34)
                DropFrame.BackgroundColor3 = Color3.fromRGB(25, 25, 35)
                DropFrame.BorderSizePixel = 0
                DropFrame.ClipsDescendants = true
                DropFrame.Parent = SectionFrame
                
                local DropCorner = Instance.new("UICorner")
                DropCorner.CornerRadius = UDim.new(0, 6)
                DropCorner.Parent = DropFrame
                
                local DropBtn = Instance.new("TextButton")
                DropBtn.Size = UDim2.new(1, 0, 0, 34)
                DropBtn.BackgroundTransparency = 1
                DropBtn.Font = Enum.Font.Gotham
                DropBtn.Text = "  " .. DropName
                DropBtn.TextColor3 = Color3.fromRGB(200, 200, 220)
                DropBtn.TextSize = 12
                DropBtn.TextXAlignment = Enum.TextXAlignment.Left
                DropBtn.Parent = DropFrame
                
                local Arrow = Instance.new("TextLabel")
                Arrow.Size = UDim2.new(0, 30, 0, 34)
                Arrow.Position = UDim2.new(1, -30, 0, 0)
                Arrow.BackgroundTransparency = 1
                Arrow.Font = Enum.Font.GothamBold
                Arrow.Text = "v"
                Arrow.TextColor3 = Color3.fromRGB(200, 200, 220)
                Arrow.TextSize = 12
                Arrow.Parent = DropFrame
                
                local ListContainer = Instance.new("ScrollingFrame")
                ListContainer.Size = UDim2.new(1, -10, 0, 0)
                ListContainer.Position = UDim2.new(0, 5, 0, 36)
                ListContainer.BackgroundTransparency = 1
                ListContainer.BorderSizePixel = 0
                ListContainer.CanvasSize = UDim2.new(0, 0, 0, #Options * 26)
                ListContainer.ScrollBarThickness = 3
                ListContainer.Parent = DropFrame
                
                local ListLayout = Instance.new("UIListLayout")
                ListLayout.SortOrder = Enum.SortOrder.LayoutOrder
                ListLayout.Padding = UDim.new(0, 2)
                ListLayout.Parent = ListContainer
                
                local open = false
                local selected = {}
                if IsMulti and type(Default) == "table" then
                    selected = Default
                elseif not IsMulti then
                    selected = Default or Options[1]
                end
                
                trackConnection(DropBtn.MouseButton1Click:Connect(function()
                    open = not open
                    local naturalHeight = (#Options * 26) + 6
                    local maxHeight = 160
                    local targetHeight = open and math.clamp(naturalHeight + 40, 34, maxHeight) or 34
                    local listTargetHeight = open and math.clamp(naturalHeight, 0, maxHeight - 40) or 0
                    
                    TweenService:Create(DropFrame, TweenInfo.new(0.2), {Size = UDim2.new(1, 0, 0, targetHeight)}):Play()
                    TweenService:Create(ListContainer, TweenInfo.new(0.2), {Size = UDim2.new(1, -10, 0, listTargetHeight)}):Play()
                    TweenService:Create(Arrow, TweenInfo.new(0.2), {Rotation = open and 180 or 0}):Play()
                end))
                
                for _, opt in ipairs(Options) do
                    local OptBtn = Instance.new("TextButton")
                    OptBtn.Size = UDim2.new(1, 0, 0, 24)
                    OptBtn.BackgroundColor3 = Color3.fromRGB(30, 30, 42)
                    OptBtn.BorderSizePixel = 0
                    OptBtn.Font = Enum.Font.Gotham
                    OptBtn.Text = "  " .. opt
                    
                    local isSelected = IsMulti and selected[opt] or (selected == opt)
                    OptBtn.TextColor3 = isSelected and Color3.fromRGB(0, 229, 255) or Color3.fromRGB(180, 180, 200)
                    OptBtn.TextSize = 11
                    OptBtn.TextXAlignment = Enum.TextXAlignment.Left
                    OptBtn.Parent = ListContainer
                    
                    local OptCorner = Instance.new("UICorner")
                    OptCorner.CornerRadius = UDim.new(0, 4)
                    OptCorner.Parent = OptBtn
                    
                    trackConnection(OptBtn.MouseButton1Click:Connect(function()
                        if IsMulti then
                            selected[opt] = not selected[opt]
                            OptBtn.TextColor3 = selected[opt] and Color3.fromRGB(0, 229, 255) or Color3.fromRGB(180, 180, 200)
                            Callback(selected)
                        else
                            selected = opt
                            open = false
                            TweenService:Create(DropFrame, TweenInfo.new(0.2), {Size = UDim2.new(1, 0, 0, 34)}):Play()
                            TweenService:Create(ListContainer, TweenInfo.new(0.2), {Size = UDim2.new(1, -10, 0, 0)}):Play()
                            TweenService:Create(Arrow, TweenInfo.new(0.2), {Rotation = 0}):Play()
                            Callback(selected)
                        end
                    end))
                end
            end
            
            function SectionAPI:AddButton(config)
                local BtnName = config.Name or "Button"
                local Callback = config.Callback or function() end
                
                local Btn = Instance.new("TextButton")
                Btn.Size = UDim2.new(1, 0, 0, 30)
                Btn.BackgroundColor3 = Color3.fromRGB(28, 28, 40)
                Btn.BorderSizePixel = 0
                Btn.Font = Enum.Font.GothamMedium
                Btn.Text = BtnName
                Btn.TextColor3 = Color3.fromRGB(255, 255, 255)
                Btn.TextSize = 12
                Btn.Parent = SectionFrame
                
                local BtnCorner = Instance.new("UICorner")
                BtnCorner.CornerRadius = UDim.new(0, 6)
                BtnCorner.Parent = Btn
                
                trackConnection(Btn.MouseButton1Click:Connect(function()
                    Callback()
                end))
            end
            
            return SectionAPI
        end
        
        table.insert(Tabs, {Button = TabButton, Content = TabContent})
        return TabAPI
    end
    
    return Library
end

local Window = Library:CreateWindow({Name = "saktkia51 script by draxfm | keyless cuz i felt like it"})

local CombatTab = Window:AddTab("Combat")
local SilentSec = CombatTab:AddSection("Silent Aim")

SilentSec:AddToggle({
    Name = "Enabled",
    Default = getgenv().SilentAimConfig.Enabled,
    Callback = function(v) getgenv().SilentAimConfig.Enabled = v end
})

SilentSec:AddSlider({
    Name = "FOV Radius",
    Min = 50,
    Max = 500,
    Default = getgenv().SilentAimConfig.FOV,
    Callback = function(v) getgenv().SilentAimConfig.FOV = v end
})

SilentSec:AddToggle({
    Name = "Wall Check",
    Default = getgenv().SilentAimConfig.WallCheck,
    Callback = function(v) getgenv().SilentAimConfig.WallCheck = v end
})

SilentSec:AddToggle({
    Name = "Wallbang",
    Default = getgenv().SilentAimConfig.Wallbang,
    Callback = function(v) getgenv().SilentAimConfig.Wallbang = v end
})

SilentSec:AddToggle({
    Name = "Prediction",
    Default = getgenv().SilentAimConfig.Prediction,
    Callback = function(v) getgenv().SilentAimConfig.Prediction = v end
})

SilentSec:AddDropdown({
    Name = "Target Types (Multi)",
    Options = {"Killers", "Players"},
    Multi = true,
    Default = getgenv().SilentAimConfig.TargetTypes,
    Callback = function(v) getgenv().SilentAimConfig.TargetTypes = v end
})

local OPETab = Window:AddTab("Mods")
local MovementSec = OPETab:AddSection("Movement")

local tpwalking
MovementSec:AddSlider({
    Name = "Walkspeed (bypasses detection)",
    Min = 0,
    Max = 6,
    Default = 0,
    Callback = function(v)
        pcall(function() tpwalking:Disconnect() end)
        if v <= 0 then return end

        local character = LocalPlayer.Character
        local humanoid = character and character:FindFirstChildWhichIsA("Humanoid")

        tpwalking = trackConnection(RunService.Heartbeat:Connect(function(delta)
            if not (character and humanoid and humanoid.Parent) then
                tpwalking:Disconnect()
                return
            end

            if humanoid.MoveDirection.Magnitude > 0 then
                character:TranslateBy(humanoid.MoveDirection * v * delta * 10)
            end
        end))
    end
})

local WeaponSec = OPETab:AddSection("Weapon & Combat Mods")

WeaponSec:AddLabel({
    Text = "honestly dont toggle these just use them"
})

WeaponSec:AddToggle({
    Name = "Fast Bullet Velocity",
    Default = getgenv().OPConfig.InstantHit,
    Callback = function(v) getgenv().OPConfig.InstantHit = v end
})

WeaponSec:AddToggle({
    Name = "Rapid Fire",
    Default = getgenv().OPConfig.NoCooldown,
    Callback = function(v) getgenv().OPConfig.NoCooldown = v end
})

WeaponSec:AddToggle({
    Name = "Full-Auto",
    Default = getgenv().OPConfig.Autofire,
    Callback = function(v) getgenv().OPConfig.Autofire = v end
})

WeaponSec:AddToggle({
    Name = "Infinite Ammo",
    Default = getgenv().OPConfig.InfiniteAmmo,
    Callback = function(v) getgenv().OPConfig.InfiniteAmmo = v end
})

WeaponSec:AddToggle({
    Name = "No Recoil",
    Default = getgenv().OPConfig.NoRecoil,
    Callback = function(v) getgenv().OPConfig.NoRecoil = v end
})

local HitboxSec = OPETab:AddSection("Hitbox Expander")

HitboxSec:AddLabel({
    Text = "might make some killers movement a lil quirky but gets the job done"
})

HitboxSec:AddToggle({
    Name = "Enabled",
    Default = getgenv().OPConfig.HitboxExpander.Enabled,
    Callback = function(v) getgenv().OPConfig.HitboxExpander.Enabled = v end
})

HitboxSec:AddSlider({
    Name = "Size",
    Min = 2,
    Max = 30,
    Default = getgenv().OPConfig.HitboxExpander.Size,
    Callback = function(v) getgenv().OPConfig.HitboxExpander.Size = v end
})

local ESPTab = Window:AddTab("ESP")
local ESPSec = ESPTab:AddSection("ESP Settings")

ESPSec:AddToggle({
    Name = "ESP Masterswitch",
    Default = getgenv().ESPConfig.Enabled,
    Callback = function(v) getgenv().ESPConfig.Enabled = v end
})

ESPSec:AddToggle({
    Name = "Boxes",
    Default = getgenv().ESPConfig.Box,
    Callback = function(v) getgenv().ESPConfig.Box = v end
})

ESPSec:AddToggle({
    Name = "Tracers",
    Default = getgenv().ESPConfig.Tracer,
    Callback = function(v) getgenv().ESPConfig.Tracer = v end
})

ESPSec:AddToggle({
    Name = "Health Bar",
    Default = getgenv().ESPConfig.HealthBar,
    Callback = function(v) getgenv().ESPConfig.HealthBar = v end
})

ESPSec:AddToggle({
    Name = "Skeleton",
    Default = getgenv().ESPConfig.Skeleton,
    Callback = function(v) getgenv().ESPConfig.Skeleton = v end
})

local HelperTab = Window:AddTab("Helpers")
local HelperSec = HelperTab:AddSection("Helpers")

HelperSec:AddButton({
    Name = "Apply Zombie Morph",
    Callback = function()
        local part = workspace:WaitForChild("AREA51"):WaitForChild("Outside"):WaitForChild("Hangar"):WaitForChild("Right"):WaitForChild("Zombie Morph"):WaitForChild("TheButton")
        local hrp = LocalPlayer.Character:WaitForChild("HumanoidRootPart")
        if not part or not hrp then return end
        firetouchinterest(hrp, part, false)
        Notify(scriptname, "put on zombie morph")
    end
})

local autoApplyZombieMorph = false
HelperSec:AddToggle({
    Name = "Autoapply Zombie Morph on Respawn",
    Default = false,
    Callback = function(v)
        autoApplyZombieMorph = v
        if v then
            local conn
            conn = trackConnection(LocalPlayer.CharacterAdded:Connect(function(c)
                if not autoApplyZombieMorph then
                    conn:Disconnect()
                    return
                end
                local hrp = c:WaitForChild("HumanoidRootPart")
                local part = workspace:WaitForChild("AREA51"):WaitForChild("Outside"):WaitForChild("Hangar"):WaitForChild("Right"):WaitForChild("Zombie Morph"):WaitForChild("TheButton")
                if not part or not hrp then return end
                task.wait(1)
                firetouchinterest(hrp, part, false)
            end))
        else
            autoApplyZombieMorph = false
        end
    end
})

HelperSec:AddButton({
    Name = "Get All Guns",
    Callback = function()
        for _,v in pairs(Workspace:WaitForChild("Weapons"):GetChildren()) do
            if v:IsA("Model") then
                local hitbox = v:FindFirstChild("Hitbox")
                if hitbox then
                    firetouchinterest(LocalPlayer.Character.HumanoidRootPart, hitbox, false)
                end
            end
        end
        Notify(scriptname, "got all guns good boy")
    end
})

local autoGetAllGuns = false
HelperSec:AddToggle({
    Name = "Autoget all guns on respawn",
    Default = false,
    Callback = function(v)
        autoGetAllGuns = v
        if v then
            local conn
            conn = trackConnection(LocalPlayer.CharacterAdded:Connect(function(c)
                if not autoGetAllGuns then
                    conn:Disconnect()
                    return
                end
                local hrp = c:WaitForChild("HumanoidRootPart")
                if not hrp then return end
                task.wait(1)
                for _,wp in pairs(Workspace:WaitForChild("Weapons"):GetChildren()) do
                    if wp:IsA("Model") then
                        local hitbox = wp:FindFirstChild("Hitbox")
                        if hitbox then
                            firetouchinterest(hrp, hitbox, false)
                        end
                    end
                end
            end))
        else
            autoGetAllGuns = false
        end
    end
})

local autoCollectSkinLoot = false
HelperSec:AddToggle({
    Name = "Auto Collect Skin Loot",
    Default = false,
    Callback = function(v)
        autoCollectSkinLoot = v
        if v then
            local conn
            conn = trackConnection(workspace.ChildAdded:Connect(function(c)
                if not autoCollectSkinLoot then
                    conn:Disconnect()
                    return
                end
                if c:FindFirstChild("Fire") then
                    c.CanCollide = false
                    c.CFrame = game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame
                end
            end))
        else
            autoCollectSkinLoot = false
        end
    end
})

local MoreTab = Window:AddTab("More")
local MoreSec = MoreTab:AddSection("GUI Settings")

MoreSec:AddKeybind({
    Name = "Hide GUI Keybind",
    Default = hideKeybind,
    Callback = function(key)
        hideKeybind = key
        Notify(scriptname, "Hide keybind set to " .. key.Name)
    end
})

MoreSec:AddButton({
    Name = "Unload Script (not recommended sometimes buggy)",
    Callback = function()
        for _, conn in ipairs(activeConnections) do
            if conn and typeof(conn) == "RBXScriptConnection" then
                pcall(function() conn:Disconnect() end)
            end
        end
        table.clear(activeConnections)

        pcall(function()
            cleardrawcache()
        end)

        pcall(function()
            for part, data in pairs(originalPartProperties) do
                if part and part.Parent then
                    part.Size = data.Size
                    part.Transparency = data.Transparency
                    part.CanCollide = data.CanCollide
                end
            end
            table.clear(originalPartProperties)
        end)

        pcall(function()
            for _, data in ipairs(hookedWeapons) do
                local obj = data.obj
                if obj and type(obj) == "table" then
                    if data.orig_shoot_wait ~= nil then obj.shoot_wait = data.orig_shoot_wait end
                    if data.orig_fire_wait ~= nil then obj.fire_wait = data.orig_fire_wait end
                    if data.orig_recoil_camera ~= nil then obj.recoil_camera = data.orig_recoil_camera end
                    if data.orig_inaccuracy ~= nil then obj.inaccuracy = data.orig_inaccuracy end
                    if data.orig_ammo ~= nil then obj.ammo = data.orig_ammo end
                    if data.orig_automatic ~= nil then obj.automatic = data.orig_automatic end
                    if data.orig_auto ~= nil then obj.auto = data.orig_auto end
                    if data.orig_is_auto ~= nil then obj.is_auto = data.orig_is_auto end
                    if data.orig_screen_to_target ~= nil then obj.screen_to_target = data.orig_screen_to_target end
                    if data.orig_target_ray_callback ~= nil then obj.target_ray_callback = data.orig_target_ray_callback end
                    if data.orig_missile_hit ~= nil then obj.missile_hit = data.orig_missile_hit end
                end
            end
        end)

        pcall(function() ScreenGui:Destroy() end)
        pcall(function() NotificationGui:Destroy() end)

        getgenv().SilentAimConfig = nil
        getgenv().ESPConfig = nil
        getgenv().OPConfig = nil
        getgenv().draxfm_saktkia51 = nil
    end
})

local CreditsSec = MoreTab:AddSection("Information & Credits")
CreditsSec:AddLabel({
    Text = "made with <3 by draxfm | discord.gg/sEXECdC3Et"
})
CreditsSec:AddLabel({
    Text = "script is pretty vibecoded. wanted to see if AI could actually make good UI, well thats the product"
})
CreditsSec:AddLabel({
    Text = "you like that ts is keyless and open src? join my dc or buy an exec using the link below if you're a goat"
})
CreditsSec:AddButton({
    Name = "Copy Discord Invite Link",
    Callback = function()
        Notify(scriptname, "dc invite link copied", 4)
        setclipboard("https://discord.gg/sEXECdC3Et")
        reqDcJoin()
    end
})
CreditsSec:AddButton({
    Name = "Copy Link to Premium Executors, Externals & Scripts",
    Callback = function()
        Notify(scriptname, "rcheatz link copied", 4)
        setclipboard("https://rcheatz.com/?ref=drax")
    end
})

local FOVCircle = Drawing.new("Circle")
FOVCircle.Visible = getgenv().SilentAimConfig.ShowFOV
FOVCircle.Transparency = 0.8
FOVCircle.Color = getgenv().SilentAimConfig.FOVColor
FOVCircle.Thickness = getgenv().SilentAimConfig.FOVThickness
FOVCircle.Filled = false
FOVCircle.Radius = getgenv().SilentAimConfig.FOV

trackConnection(RunService.RenderStepped:Connect(function()
    local Config = getgenv().SilentAimConfig
    if not Config.Enabled then
        FOVCircle.Visible = false
        return
    end

    FOVCircle.Visible = Config.ShowFOV
    FOVCircle.Radius = Config.FOV
    FOVCircle.Color = Config.FOVColor
    FOVCircle.Position = UserInputService:GetMouseLocation() or (Camera.ViewportSize / 2)
end))

local function IsValidTarget(model)
    if not model or not model:IsA("Model") then return false end
    if BlacklistedNames[model.Name] then return false end
    
    local humanoid = model:FindFirstChildOfClass("Humanoid")
    if not humanoid or humanoid.Health <= 0 then return false end
    if humanoid.Parent == LocalPlayer.Character then return false end

    local types = getgenv().SilentAimConfig.TargetTypes
    local isTarget = false
    
    if types.Killers and KillersFolder and model:IsDescendantOf(KillersFolder) then isTarget = true end
    if types.Players and CharactersToKillFolder and model:IsDescendantOf(CharactersToKillFolder) then isTarget = true end
    
    return isTarget
end

local function IsVisible(targetPart, character)
    local Config = getgenv().SilentAimConfig
    if not Config.WallCheck or Config.Wallbang then return true end
    
    local origin = Camera.CFrame.Position
    local direction = (targetPart.Position - origin)
    
    local raycastParams = RaycastParams.new()
    raycastParams.FilterType = Enum.RaycastFilterType.Exclude
    raycastParams.FilterDescendantsInstances = {LocalPlayer.Character, character}
    raycastParams.IgnoreWater = true

    local result = Workspace:Raycast(origin, direction, raycastParams)
    return result == nil or result.Instance:IsDescendantOf(character)
end

local function GetClosestTarget()
    local Config = getgenv().SilentAimConfig
    local closestTargetPart = nil
    local closestPredictedPos = nil
    local shortestDistance = Config.FOV
    local mousePos = UserInputService:GetMouseLocation()

    local function evaluateCharacter(model)
        if not IsValidTarget(model) then return end
        
        local targetPart = model:FindFirstChild(Config.TargetPart) or model:FindFirstChild("Head")
        local rootPart = model:FindFirstChild("HumanoidRootPart") or model:FindFirstChild("Torso")

        if targetPart then
            local predictedPos = targetPart.Position
            
            if Config.Prediction and rootPart then
                local distance = (Camera.CFrame.Position - targetPart.Position).Magnitude
                local bulletSpeed = getgenv().OPConfig.InstantHit and 99999 or 150
                local travelTime = distance / bulletSpeed
                predictedPos = targetPart.Position + (rootPart.AssemblyLinearVelocity * travelTime * Config.PredictionFactor)
            end

            local screenPos, onScreen = Camera:WorldToViewportPoint(predictedPos)
            if onScreen then
                local distance = (Vector2.new(screenPos.X, screenPos.Y) - mousePos).Magnitude
                if distance < shortestDistance then
                    if IsVisible(targetPart, model) then
                        shortestDistance = distance
                        closestTargetPart = targetPart
                        closestPredictedPos = predictedPos
                    end
                end
            end
        end
    end

    local types = Config.TargetTypes
    if types.Killers and KillersFolder then
        for _, v in ipairs(KillersFolder:GetChildren()) do evaluateCharacter(v) end
    end
    if types.Players and CharactersToKillFolder then
        for _, v in ipairs(CharactersToKillFolder:GetChildren()) do evaluateCharacter(v) end
    end

    return closestTargetPart, closestPredictedPos
end

local originalPartProperties = {}

trackConnection(RunService.RenderStepped:Connect(function()
    local OPConf = getgenv().OPConfig
    
    if not OPConf.HitboxExpander.Enabled then
        for part, data in pairs(originalPartProperties) do
            if part and part.Parent then
                part.Size = data.Size
                part.Transparency = data.Transparency
                part.CanCollide = data.CanCollide
            end
        end
        table.clear(originalPartProperties)
        return
    end

    local function expandHitbox(model)
        if not IsValidTarget(model) then return end
        local part = model:FindFirstChild(OPConf.HitboxExpander.TargetPart) or model:FindFirstChild("HumanoidRootPart")
        if part and part:IsA("BasePart") then
            if not originalPartProperties[part] then
                originalPartProperties[part] = {
                    Size = part.Size,
                    Transparency = part.Transparency,
                    CanCollide = false
                }
            end
            local expSize = OPConf.HitboxExpander.Size
            part.Size = Vector3.new(expSize, expSize, expSize)
            part.Transparency = OPConf.HitboxExpander.Transparency
            part.CanCollide = false
        end
    end

    if KillersFolder then for _, v in ipairs(KillersFolder:GetChildren()) do expandHitbox(v) end end
    if CharactersToKillFolder then for _, v in ipairs(CharactersToKillFolder:GetChildren()) do expandHitbox(v) end end
end))

local hookedWeapons = {}

task.spawn(function()
    repeat task.wait(1) until getgc and debug
    for _, obj in ipairs(getgc(true)) do
        if type(obj) == "table" then
            if rawget(obj, "shoot_wait") or rawget(obj, "recoil_camera") or rawget(obj, "ammo") or rawget(obj, "screen_to_target") then
                table.insert(hookedWeapons, {
                    obj = obj,
                    orig_shoot_wait = obj.shoot_wait,
                    orig_fire_wait = obj.fire_wait,
                    orig_recoil_camera = obj.recoil_camera,
                    orig_inaccuracy = obj.inaccuracy,
                    orig_ammo = obj.ammo,
                    orig_automatic = obj.automatic,
                    orig_auto = obj.auto,
                    orig_is_auto = obj.is_auto,
                    orig_screen_to_target = rawget(obj, "screen_to_target"),
                    orig_target_ray_callback = rawget(obj, "target_ray_callback"),
                    orig_missile_hit = rawget(obj, "missile_hit"),
                })
                
                if rawget(obj, "screen_to_target") then
                    local originalScreenToTarget = obj.screen_to_target
                    local originalMissileHit = obj.missile_hit
                    
                    obj.screen_to_target = function(self, inputFunc, ...)
                        local Config = getgenv().SilentAimConfig
                        if Config and Config.Enabled then
                            local targetPart, predictedPos = GetClosestTarget()
                            if predictedPos then return predictedPos end
                        end
                        return originalScreenToTarget(self, inputFunc, ...)
                    end

                    if rawget(obj, "target_ray_callback") then
                        local originalRayCallback = obj.target_ray_callback
                        obj.target_ray_callback = function(raycastResult, ...)
                            local Config = getgenv().SilentAimConfig
                            if Config and Config.Enabled and Config.Wallbang and raycastResult and raycastResult.Instance then
                                local model = raycastResult.Instance.Parent
                                if IsValidTarget(model) then return true else return false end
                            end
                            return originalRayCallback(raycastResult, ...)
                        end
                    end

                    if originalMissileHit then
                        obj.missile_hit = function(self, missile, moment, hitPart, missilePos, ...)
                            local Config = getgenv().SilentAimConfig
                            if Config and Config.Enabled and Config.Wallbang and hitPart then
                                local model = hitPart.Parent
                                if not IsValidTarget(model) and hitPart.CanCollide then return end
                            end
                            return originalMissileHit(self, missile, moment, hitPart, missilePos, ...)
                        end
                    end
                end
            end
        end
    end
end)

trackConnection(RunService.RenderStepped:Connect(function()
    local OPConf = getgenv().OPConfig
    for _, data in ipairs(hookedWeapons) do
        local obj = data.obj
        if obj and type(obj) == "table" then
            if OPConf.NoCooldown then
                if rawget(obj, "shoot_wait") ~= nil then obj.shoot_wait = 0 end
                if rawget(obj, "fire_wait") ~= nil then obj.fire_wait = function() task.wait() end end
            else
                if data.orig_shoot_wait ~= nil then obj.shoot_wait = data.orig_shoot_wait end
                if data.orig_fire_wait ~= nil then obj.fire_wait = data.orig_fire_wait end
            end

            if OPConf.Autofire then
                if rawget(obj, "is_auto") ~= nil then obj.is_auto = true end
                if rawget(obj, "automatic") ~= nil then obj.automatic = true end
                if rawget(obj, "auto") ~= nil then obj.auto = true end
            else
                if data.orig_is_auto ~= nil then obj.is_auto = data.orig_is_auto end
                if data.orig_automatic ~= nil then obj.automatic = data.orig_automatic end
                if data.orig_auto ~= nil then obj.auto = data.orig_auto end
            end

            if OPConf.NoRecoil then
                if rawget(obj, "recoil_camera") ~= nil then obj.recoil_camera = function() end end
                if rawget(obj, "inaccuracy") ~= nil then obj.inaccuracy = 0 end
            else
                if data.orig_recoil_camera ~= nil then obj.recoil_camera = data.orig_recoil_camera end
                if data.orig_inaccuracy ~= nil then obj.inaccuracy = data.orig_inaccuracy end
            end

            if OPConf.InfiniteAmmo then
                if rawget(obj, "ammo") ~= nil then obj.ammo = math.huge end
            else
                if data.orig_ammo ~= nil then obj.ammo = data.orig_ammo end
            end
        end
    end
end))

trackConnection(Workspace.ChildAdded:Connect(function(child)
    if getgenv().OPConfig.InstantHit and child.Name == "Bullet" then
        task.defer(function()
            if child and child.Parent then
                child.AssemblyLinearVelocity = child.AssemblyLinearVelocity * 10
            end
        end)
    end
end))

local activeEspDrawings = {}

local function removeEsp(model)
    if activeEspDrawings[model] then
        for _, drawing in pairs(activeEspDrawings[model]) do
            if type(drawing) == "table" then
                for _, subDrawing in pairs(drawing) do
                    pcall(function() subDrawing:Remove() end)
                end
            else
                pcall(function() drawing:Remove() end)
            end
        end
        activeEspDrawings[model] = nil
    end
end

local function createEspDrawings()
    return {
        Box = Drawing.new("Square"),
        Tracer = Drawing.new("Line"),
        HealthBarBg = Drawing.new("Square"),
        HealthBar = Drawing.new("Square"),
        Name = Drawing.new("Text"),
        Distance = Drawing.new("Text"),
        Skeleton = {
            HeadToTorso = Drawing.new("Line"),
            TorsoToLArm = Drawing.new("Line"),
            TorsoToRArm = Drawing.new("Line"),
            TorsoToLLeg = Drawing.new("Line"),
            TorsoToRLeg = Drawing.new("Line"),
        }
    }
end

local function GetModelBoundingBoxWithoutExpansion(model)
    local min = Vector3.new(math.huge, math.huge, math.huge)
    local max = Vector3.new(-math.huge, -math.huge, -math.huge)
    local hasParts = false

    for _, part in ipairs(model:GetDescendants()) do
        if part:IsA("BasePart") then
            hasParts = true
            local pSize = (originalPartProperties[part] and originalPartProperties[part].Size) or part.Size
            local pCFrame = part.CFrame
            local halfSize = pSize / 2
            for x = -1, 1, 2 do
                for y = -1, 1, 2 do
                    for z = -1, 1, 2 do
                        local corner = (pCFrame * CFrame.new(halfSize.X * x, halfSize.Y * y, halfSize.Z * z)).Position
                        min = Vector3.new(math.min(min.X, corner.X), math.min(min.Y, corner.Y), math.min(min.Z, corner.Z))
                        max = Vector3.new(math.max(max.X, corner.X), math.max(max.Y, corner.Y), math.max(max.Z, corner.Z))
                    end
                end
            end
        end
    end

    if not hasParts then return model:GetBoundingBox() end

    local center = (min + max) / 2
    local boxSize = max - min
    return CFrame.new(center), boxSize
end

trackConnection(RunService.RenderStepped:Connect(function()
    local ESPConf = getgenv().ESPConfig

    if not ESPConf.Enabled then
        for model, _ in pairs(activeEspDrawings) do removeEsp(model) end
        return
    end

    local currentModels = {}

    local function evaluateForEsp(model)
        if not model or not model:IsA("Model") then return end
        if BlacklistedNames[model.Name] then return end
        local humanoid = model:FindFirstChildOfClass("Humanoid")
        local rootPart = model:FindFirstChild("HumanoidRootPart") or model:FindFirstChild("Torso") or model:FindFirstChild("Head")
        if not humanoid or humanoid.Health <= 0 or not rootPart then return end
        if model == LocalPlayer.Character then return end
        currentModels[model] = {model = model, humanoid = humanoid, rootPart = rootPart}
    end

    if KillersFolder then for _, v in ipairs(KillersFolder:GetChildren()) do evaluateForEsp(v) end end
    if CharactersToKillFolder then for _, v in ipairs(CharactersToKillFolder:GetChildren()) do evaluateForEsp(v) end end

    for model, _ in pairs(activeEspDrawings) do
        if not currentModels[model] then removeEsp(model) end
    end

    for model, data in pairs(currentModels) do
        local drawings = activeEspDrawings[model]
        if not drawings then
            drawings = createEspDrawings()
            activeEspDrawings[model] = drawings
        end

        local rootPart = data.rootPart
        local humanoid = data.humanoid
        local color = (KillersFolder and model:IsDescendantOf(KillersFolder)) and ESPConf.KillerColor or ESPConf.PlayerColor
        local rootPos, onScreen = Camera:WorldToViewportPoint(rootPart.Position)

        if onScreen then
            local distance = (Camera.CFrame.Position - rootPart.Position).Magnitude
            local cframe, size = GetModelBoundingBoxWithoutExpansion(model)
            local topScreen = Camera:WorldToViewportPoint(cframe.Position + Vector3.new(0, size.Y / 2, 0))
            local bottomScreen = Camera:WorldToViewportPoint(cframe.Position - Vector3.new(0, size.Y / 2, 0))
            local boxHeight = math.abs(topScreen.Y - bottomScreen.Y)
            local boxWidth = boxHeight * 0.65
            local boxPos = Vector2.new(rootPos.X - boxWidth / 2, topScreen.Y)

            if ESPConf.Box then
                drawings.Box.Visible = true
                drawings.Box.Size = Vector2.new(boxWidth, boxHeight)
                drawings.Box.Position = boxPos
                drawings.Box.Color = color
                drawings.Box.Thickness = 1
            else
                drawings.Box.Visible = false
            end

            if ESPConf.Tracer then
                drawings.Tracer.Visible = true
                drawings.Tracer.From = Vector2.new(Camera.ViewportSize.X / 2, Camera.ViewportSize.Y)
                drawings.Tracer.To = Vector2.new(rootPos.X, rootPos.Y)
                drawings.Tracer.Color = color
                drawings.Tracer.Thickness = 1
            else
                drawings.Tracer.Visible = false
            end

            if ESPConf.HealthBar then
                local healthPercent = math.clamp(humanoid.Health / (humanoid.MaxHealth > 0 and humanoid.MaxHealth or 100), 0, 1)
                local barHeight = math.floor(boxHeight * healthPercent)
                local barX = boxPos.X - 9

                drawings.HealthBarBg.Visible = true
                drawings.HealthBarBg.Size = Vector2.new(5, boxHeight + 2)
                drawings.HealthBarBg.Position = Vector2.new(barX - 1, boxPos.Y - 1)
                drawings.HealthBarBg.Color = Color3.fromRGB(0, 0, 0)
                drawings.HealthBarBg.Filled = true

                drawings.HealthBar.Visible = true
                drawings.HealthBar.Size = Vector2.new(3, barHeight)
                drawings.HealthBar.Position = Vector2.new(barX, boxPos.Y + (boxHeight - barHeight))
                drawings.HealthBar.Color = Color3.fromRGB(255, 0, 0):Lerp(Color3.fromRGB(0, 255, 0), healthPercent)
                drawings.HealthBar.Filled = true
            else
                drawings.HealthBar.Visible = false
                drawings.HealthBarBg.Visible = false
            end

            if ESPConf.Name then
                drawings.Name.Visible = true
                drawings.Name.Text = model.Name
                drawings.Name.Size = 13
                drawings.Name.Center = true
                drawings.Name.Outline = true
                drawings.Name.Color = color
                drawings.Name.Position = Vector2.new(boxPos.X + boxWidth / 2, boxPos.Y - 18)
            else
                drawings.Name.Visible = false
            end

            if ESPConf.Distance then
                drawings.Distance.Visible = true
                drawings.Distance.Text = math.floor(distance) .. " studs"
                drawings.Distance.Size = 12
                drawings.Distance.Center = true
                drawings.Distance.Outline = true
                drawings.Distance.Color = Color3.fromRGB(255, 255, 255)
                drawings.Distance.Position = Vector2.new(boxPos.X + boxWidth / 2, boxPos.Y + boxHeight + 4)
            else
                drawings.Distance.Visible = false
            end

            if ESPConf.Skeleton then
                local head = model:FindFirstChild("Head")
                local torso = model:FindFirstChild("Torso") or model:FindFirstChild("UpperTorso")
                local lArm = model:FindFirstChild("Left Arm") or model:FindFirstChild("LeftUpperArm") or model:FindFirstChild("LeftHand")
                local rArm = model:FindFirstChild("Right Arm") or model:FindFirstChild("RightUpperArm") or model:FindFirstChild("RightHand")
                local lLeg = model:FindFirstChild("Left Leg") or model:FindFirstChild("LeftLowerLeg") or model:FindFirstChild("LeftFoot")
                local rLeg = model:FindFirstChild("Right Leg") or model:FindFirstChild("RightLowerLeg") or model:FindFirstChild("RightFoot")

                local function drawBone(boneLine, partA, partB)
                    if partA and partB then
                        local screenA, visA = Camera:WorldToViewportPoint(partA.Position)
                        local screenB, visB = Camera:WorldToViewportPoint(partB.Position)
                        if visA and visB then
                            boneLine.Visible = true
                            boneLine.From = Vector2.new(screenA.X, screenA.Y)
                            boneLine.To = Vector2.new(screenB.X, screenB.Y)
                            boneLine.Color = color
                            boneLine.Thickness = 1
                            return
                        end
                    end
                    boneLine.Visible = false
                end

                drawBone(drawings.Skeleton.HeadToTorso, head, torso)
                drawBone(drawings.Skeleton.TorsoToLArm, torso, lArm)
                drawBone(drawings.Skeleton.TorsoToRArm, torso, rArm)
                drawBone(drawings.Skeleton.TorsoToLLeg, torso, lLeg)
                drawBone(drawings.Skeleton.TorsoToRLeg, torso, rLeg)
            else
                for _, bone in pairs(drawings.Skeleton) do bone.Visible = false end
            end
        else
            drawings.Box.Visible = false
            drawings.Tracer.Visible = false
            drawings.HealthBar.Visible = false
            drawings.HealthBarBg.Visible = false
            drawings.Name.Visible = false
            drawings.Distance.Visible = false
            for _, bone in pairs(drawings.Skeleton) do bone.Visible = false end
        end
    end
end))

trackConnection(UserInputService.InputBegan:Connect(function(input, gameProcessed)
    if not gameProcessed and input.KeyCode == hideKeybind then
        ScreenGui.Enabled = not ScreenGui.Enabled
    end
end))

reqDcJoin()
Notify(scriptname, "script loaded. RightShift to toggle UI", 5)
