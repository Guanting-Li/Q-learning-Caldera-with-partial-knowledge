import numpy as np
import asyncio
import time
import random
import pandas


class LogicalPlanner:

    def __init__(self, operation, planning_svc, stopping_conditions=()):
        self.operation = operation
        self.planning_svc = planning_svc
        self.stopping_conditions = stopping_conditions
        self.stopping_condition_met = False
        self.state_machine = ['atomic']
        self.next_bucket = 'atomic'
        self.q_tables = []
        self.states = ['agent-deployed', 'privilege-escalation', 'persistence', 'privilege-escalation&persistence']
        self.timeout = 60
        self.alpha = 0.1
        self.gamma = 0.6
        self.epsilon = 0.4  # was 0.1
        self.rewards = {
        'discovery': 1,
        'privilege-escalation': 3,
        'persistence': 3,
        'collection': 1,
        'lateral-movement': 5
    }

    async def execute(self):
        await self.planning_svc.execute_planner(self)

    async def atomic(self):
        # links_to_use = []

        ability_links = await self.planning_svc.get_links(self.operation)
        paw = ability_links[0].paw if ability_links else None
        links_to_use = [await self.operation.apply(l) for l in ability_links]

        name_of_links = [link.ability.name for link in ability_links]

        # create new q table
        # q_table = np.zeros((len(self.states), len(links_to_use)))
        unconverged_q_tables = []
        q_table = self.generate_q_table(name_of_links)
        unconverged_q_tables.append(q_table)

        while len(unconverged_q_tables) != 0:
            q_table = unconverged_q_tables.pop()
            for i in range(6):

                # if i == 2:
                #     # make second q table
                #     self.q_tables.append(q_table)
                #     q_table = self.generate_q_table(name_of_links)

                print("\n\n\n---------------------number of epochs: -----{}-------------\n\n\n".format(i+1))
                # reset the state
                state = 'agent-deployed'

                done = False

                time_start = time.time()

                while not done:
                    # stop the epoch after certain amount of time
                    if time.time() > time_start + self.timeout:
                        done = True

                    # choose the next action
                    if random.uniform(0, 1) < self.epsilon:
                        link = random.choice(name_of_links)
                    else:
                        print("\nuse the current best strategy")
                        link = max(q_table[state], key=q_table[state].get)

                    next_state, reward, done = await self._wait_for_link_completion(link, state)

                    print("_____next_state = {}, reward = {}, done = {}______".format(next_state, reward, done))
                    # update q table value
                    old_value = q_table[state][link]
                    next_max = max(q_table[next_state].values())

                    new_value = (1 - self.alpha) * old_value + self.alpha * (reward + self.gamma * next_max)
                    q_table[state][link] = new_value

                    state = next_state

                    # recreate new links to make sure links can be executed repeatedly
                    await asyncio.sleep(5)
                    links_to_use = []
                    self.operation.remove_all_links()

                    ability_links = await self.planning_svc.get_links(self.operation)
                    paw = ability_links[0].paw if ability_links else None
                    links_to_use = [await self.operation.apply(l) for l in ability_links]

                    name_of_links = [link.ability.name for link in ability_links]

                    print("\n\n-------------------")
                    print("Q_table:")
                    for key in q_table.keys():
                        print("\n{}: {}".format(key, q_table[key]))
                    print("-------------------")

            self.q_tables.append(q_table)

        self.generate_report()
        self.operation.state = self.operation.states['FINISHED']

    def generate_q_table(self, name_of_links):
        q_table = dict.fromkeys(self.states)
        for state in q_table:
            q_table[state] = dict.fromkeys(name_of_links, 0)
        return q_table

    def generate_report(self):
        print("\n\n\n\n#############The final report###############")
        for i in range(len(self.q_tables)):
            q_table = self.q_tables[i]
            print("\n\n")
            q_table_info = f"----Agent#paw: {self.operation.agents[i].paw}---Host: {self.operation.agents[i].host}---\n"
            print(q_table_info)

            data = []
            for state in q_table:
                data.append([state, max(q_table[state], key=q_table[state].get)])

            headers = ["Current State", "Best next ability"]
            data = pandas.DataFrame(data)
            data.columns = headers
            print(data)

    # execute a single action
    async def _wait_for_link_completion(self, link_name, state):

        # initialise done value
        done = False

        print("\n------The current state: {}-----".format(state))
        print("\n------The chosen link_: {}-------".format(link_name))

        link = [link for link in self.operation.chain if link.ability.name == link_name][0]
        member = [member for member in self.operation.agents if member.paw == link.paw][0]

        while not (link.is_finished() or link.can_ignore()):
            await asyncio.sleep(5)
            print('5 seconds passed, waiting for the execution of the chosen link')
            if not member.trusted:
                break

        bucket = link.ability.buckets[0]

        # generate reward
        reward = 0
        if link.status == 0:  # 0 is the return value of a successful link
            reward = 1
            if bucket in self.rewards.keys():
                reward = reward * self.rewards[bucket]  # could have multiple buckets but use the first one for test purpose
        else:
            reward = -1

        # generate new state
        new_state = state
        if reward > 0:
            if bucket == 'lateral-movement':
                # add a new agent and add a new q table
                self.q_tables.append(np.zeros([len(self.states), len(self.links_to_use)]))
                print("#######trigger lateral-movement###############")
                pass
            elif state == 'agent-deployed':
                if bucket == 'privilege-escalation':
                    new_state = 'privilege-escalation'
                elif bucket == 'persistence':
                    new_state = 'persistence'

            elif state == 'privilege-escalation':
                if bucket == 'persistence':
                    new_state = 'privilege-escalation&persistence'

            elif state == 'persistence':
                if bucket == 'privilege-escalation':
                    new_state = 'privilege-escalation&persistence'

        # reward for state change
        if new_state != state:
            reward += 10

        # update done @@@
        if bucket == 'lateral-movement' and state == 'privilege-escalation&persistence':
            reward += 15
            done = True

        # reset the status of link from finished to execute
        # link.status(-3)
        # link.status = link.states['EXECUTE']

        # change status of link and pause to wait the event to be executed
        # if link.status != -3:
        #     # link._emit_status_change_event(link.status, -3)
        #     link.status.setter(-3)
        #     # link.status = link.states['EXECUTE']
        #     await asyncio.sleep(5)

        # print("----link updated status: {}----".format(link.status))

        # remove the executed link and create a new one.

        return new_state, reward, done

    async def _get_links(self, agent=None):
        return await self.planning_svc.get_links(operation=self.operation, agent=agent)

    # Given list of links, returns the link that appears first in the adversary's atomic ordering.
    async def _get_next_atomic_link(self, links):
        abil_id_to_link = dict()
        for link in links:
            abil_id_to_link[link.ability.ability_id] = link
        candidate_ids = set(abil_id_to_link.keys())
        for ab_id in self.operation.adversary.atomic_ordering:
            if ab_id in candidate_ids:
                return abil_id_to_link[ab_id]
